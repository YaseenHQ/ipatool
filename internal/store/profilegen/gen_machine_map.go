package profilegen

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"os"
	"sort"

	"github.com/blacktop/go-macho"
	"github.com/majd/ipatool/v2/internal/sap/assets"
)

// GenerateMachineMaps scans an extracted AppleMediaServices Mach-O for
// shared-cache pointer values, resolves each to a symbol name using the full
// cache symbol index, and emits the prelinked function/slot maps.
func GenerateMachineMaps(ctx context.Context, cache *assets.StoreCache, imagePath string) error {
	s, err := newSource(ctx, cache)
	if err != nil {
		return err
	}

	defer s.close()

	// Load the dependency closure first, then every remaining cache image so
	// symbol resolution covers the whole shared cache.
	images, err := cache.Images()
	if err != nil {
		return fmt.Errorf("list cache images: %w", err)
	}

	for name := range images {
		if _, ok := s.images[name]; !ok {
			_ = s.loadImage(name)
		}
	}

	loaded := 0

	for name := range s.images {
		if !s.symbolsLoaded[name] {
			loadSymbolsSafe(s, s.images[name])
			s.symbolsLoaded[name] = true
		}

		loaded++
	}

	fmt.Fprintf(os.Stderr, "loaded %d cache images, %d exports, %d symbols\n", loaded, len(s.exports), len(s.symbols))

	// Reverse symbol index, keeping both underscore variants.
	byName := map[string]uint64{}
	for address, name := range s.symbols {
		if _, ok := byName[name]; !ok {
			byName[name] = address
		}

		withUnderscore := "_" + name
		if _, ok := byName[withUnderscore]; !ok {
			byName[withUnderscore] = address
		}
	}

	for name, address := range s.exports {
		if _, ok := byName[name]; !ok {
			byName[name] = address
		}
	}

	// Scan the extracted image exactly like Image.PreparePrelinked does.
	data, err := os.ReadFile(imagePath)
	if err != nil {
		return fmt.Errorf("read extracted image: %w", err)
	}

	low, high := cache.AddressRange()

	type entry struct {
		address uint64
		name    string
	}

	var found []entry
	unresolved := map[uint64]bool{}

	machoImage, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		return fmt.Errorf("parse extracted image: %w", err)
	}

	for _, seg := range machoImage.Segments() {
		if seg.Name == "__TEXT" || seg.Name == "__LINKEDIT" || seg.Filesz < 8 {
			continue
		}

		fileEnd := seg.Offset + seg.Filesz
		for fileOff := seg.Offset; fileOff+8 <= fileEnd; fileOff += 8 {
			if fileOff+8 > uint64(len(data)) {
				break
			}

			value := binary.LittleEndian.Uint64(data[fileOff : fileOff+8])
			if value < low || value >= high {
				continue
			}

			name := s.symbol(value)
			if name == "" {
				unresolved[value] = true

				continue
			}

			found = append(found, entry{address: value, name: "_" + name})
		}
	}

	sort.Slice(found, func(i, j int) bool { return found[i].address < found[j].address })

	for _, item := range found {
		fmt.Printf("functions[%#x] = %q\n", item.address, item.name)
	}

	for value := range unresolved {
		fmt.Fprintf(os.Stderr, "UNRESOLVED cache pointer: %#x\n", value)
	}

	return nil
}

func loadSymbolsSafe(s *source, f *macho.File) {
	defer func() {
		_ = recover()
	}()

	s.loadSymbols(f)
}
