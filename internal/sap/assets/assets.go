package assets

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
)

const (
	macOSVersion        = "27.3"
	macOSBuild          = "26C5035r"
	macOSRestoreURL     = "https://updates.cdn-apple.com/2026FallFCS/59241290-5d51-4ca8-9df4-31624b9a4eac/UniversalMac_27.0.1_26A434_Restore.ipsw" // unused when the local asset cache is pre-seeded
	assetCacheDirectory = "apple-assets-macos-27-26C5035r-arm64-v1"
)

type Bundle struct {
	AppleMediaServices []byte
	Commerce           []byte
	CoreFP             []byte
	CoreFPICXS         []byte
}

type fileSpec struct {
	name   string
	size   int
	digest [32]byte
}

var requiredFiles = []fileSpec{
	{
		name:   "AppleMediaServices",
		size:   15191040,
		digest: mustDigest("e99e29bfbc699f6440d057679d58eda6ef1ad1021a23564df1c6fcc2b1261b62"),
	},
	{
		name:   "commerce",
		size:   8092752,
		digest: mustDigest("6cff5d4e5f84525d07c2e55e73a66823420a87111366d714aa9d510ca38e37b2"),
	},
	{
		name:   "CoreFP",
		size:   95235760,
		digest: mustDigest("94e00fac067f28543a969b14f1d463e623e624b32cae1a9367e14131e64f99cb"),
	},
	{
		name:   "CoreFP.icxs",
		size:   7365344,
		digest: mustDigest("cb8f55330ec567da3e692dab5f5388bed0312dd9093340477c5759078cc2aa7b"),
	},
}

// Load resolves and caches the pinned macOS framework profile used by SAP,
// kbsync generation, and package decryption.
func Load(ctx context.Context) (Bundle, error) {
	if ctx == nil {
		return Bundle{}, errors.New("apple asset context is nil")
	}

	if err := ctx.Err(); err != nil {
		return Bundle{}, fmt.Errorf("load Apple assets: %w", err)
	}

	directory, err := cacheDirectory()
	if err != nil {
		return Bundle{}, err
	}

	if bundle, err := readCache(directory); err == nil {
		return bundle, nil
	}

	bundle, err := resolveRemoteImage(ctx)
	if err != nil {
		return Bundle{}, err
	}

	if err := writeCache(directory, bundle); err != nil {
		return Bundle{}, fmt.Errorf("cache Apple SAP assets: %w", err)
	}

	return bundle, nil
}

func cacheDirectory() (string, error) {
	root, err := os.UserCacheDir()
	if err != nil {
		return "", fmt.Errorf("find user cache directory: %w", err)
	}

	return filepath.Join(root, "ipatool", "sap", assetCacheDirectory), nil
}

func readCache(directory string) (Bundle, error) {
	files := make(map[string][]byte, len(requiredFiles))

	for _, spec := range requiredFiles {
		data, err := readCacheFile(filepath.Join(directory, spec.name), spec.size)
		if err != nil {
			return Bundle{}, fmt.Errorf("read cached Apple SAP asset %s: %w", spec.name, err)
		}

		files[spec.name] = data
	}

	bundle := bundleFrom(files)
	if err := validate(bundle); err != nil {
		return Bundle{}, err
	}

	return bundle, nil
}

func readCacheFile(path string, expectedSize int) ([]byte, error) {
	if expectedSize < 0 {
		return nil, errors.New("invalid expected size")
	}

	file, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open cached asset: %w", err)
	}

	defer file.Close()

	info, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect cached asset: %w", err)
	}

	if info.Size() != int64(expectedSize) {
		return nil, fmt.Errorf("has size %d, expected %d", info.Size(), expectedSize)
	}

	data := make([]byte, expectedSize)
	if _, err := io.ReadFull(file, data); err != nil {
		return nil, fmt.Errorf("read cached asset: %w", err)
	}

	var extra [1]byte
	if count, err := io.ReadFull(file, extra[:]); err == nil || count != 0 {
		return nil, fmt.Errorf("grew beyond expected size %d while being read", expectedSize)
	} else if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("verify cached asset length: %w", err)
	}

	return data, nil
}

func writeCache(directory string, bundle Bundle) error {
	if err := validate(bundle); err != nil {
		return err
	}

	if err := os.MkdirAll(directory, 0o700); err != nil {
		return fmt.Errorf("create SAP asset cache: %w", err)
	}

	files := bundleFiles(bundle)
	for _, spec := range requiredFiles {
		if err := replaceFile(filepath.Join(directory, spec.name), files[spec.name]); err != nil {
			return fmt.Errorf("write cached SAP asset %s: %w", spec.name, err)
		}
	}

	return nil
}

func replaceFile(path string, data []byte) error {
	temporary, err := os.CreateTemp(filepath.Dir(path), ".download-*")
	if err != nil {
		return fmt.Errorf("create temporary cache file: %w", err)
	}

	temporaryPath := temporary.Name()
	defer os.Remove(temporaryPath)

	if err := temporary.Chmod(0o600); err != nil {
		_ = temporary.Close()

		return fmt.Errorf("set cache file permissions: %w", err)
	}

	if _, err := temporary.Write(data); err != nil {
		_ = temporary.Close()

		return fmt.Errorf("write temporary cache file: %w", err)
	}

	if err := temporary.Close(); err != nil {
		return fmt.Errorf("close temporary cache file: %w", err)
	}

	if err := os.Rename(temporaryPath, path); err == nil {
		return nil
	}

	if err := os.Remove(path); err != nil && !errors.Is(err, fs.ErrNotExist) {
		return fmt.Errorf("remove existing cache file: %w", err)
	}

	if err := os.Rename(temporaryPath, path); err != nil {
		return fmt.Errorf("install cache file: %w", err)
	}

	return nil
}

func validate(bundle Bundle) error {
	files := bundleFiles(bundle)
	for _, spec := range requiredFiles {
		data := files[spec.name]
		if len(data) != spec.size {
			return fmt.Errorf("apple SAP asset %s has size %d, expected %d", spec.name, len(data), spec.size)
		}

		if sha256.Sum256(data) != spec.digest {
			return fmt.Errorf("apple SAP asset %s failed integrity verification", spec.name)
		}
	}

	return nil
}

func bundleFrom(files map[string][]byte) Bundle {
	return Bundle{
		AppleMediaServices: files["AppleMediaServices"],
		Commerce:           files["commerce"],
		CoreFP:             files["CoreFP"],
		CoreFPICXS:         files["CoreFP.icxs"],
	}
}

func bundleFiles(bundle Bundle) map[string][]byte {
	return map[string][]byte{
		"AppleMediaServices": bundle.AppleMediaServices,
		"commerce":           bundle.Commerce,
		"CoreFP":             bundle.CoreFP,
		"CoreFP.icxs":        bundle.CoreFPICXS,
	}
}

func mustDigest(value string) [32]byte {
	var digest [32]byte

	decoded, err := hex.DecodeString(value)
	if err != nil {
		panic(err)
	}

	if len(decoded) != len(digest) {
		panic("invalid SHA-256 length")
	}

	copy(digest[:], decoded)

	return digest
}
