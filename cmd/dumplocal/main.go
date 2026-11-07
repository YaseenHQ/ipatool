// Command dumplocal extracts Apple Store images from the local dyld shared
// cache and prints their UUIDs. Local debugging aid; not part of normal builds.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/majd/ipatool/v2/internal/sap/assets"
)

const (
	amsImage  = "/System/Library/PrivateFrameworks/AppleMediaServices.framework/Versions/A/AppleMediaServices"
	authImage = "/System/Library/Accounts/Authentication/AMSAccountAuthenticationPlugin.bundle/Contents/MacOS/AMSAccountAuthenticationPlugin"
)

func main() {
	cachePrefix := flag.String("cache", "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e", "dyld shared cache file prefix")
	outDir := flag.String("out", ".", "output directory")
	flag.Parse()

	ctx := context.Background()

	cache, err := assets.OpenLocalStoreCache(ctx, *cachePrefix)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open cache:", err)
		os.Exit(1)
	}
	defer cache.Close()

	if err := cache.ExtractImage(amsImage, *outDir+"/AppleMediaServices"); err != nil {
		fmt.Fprintln(os.Stderr, "extract AppleMediaServices:", err)
		os.Exit(1)
	}

	if err := cache.ExtractAuthenticationPlugin(*outDir + "/AMSAccountAuthenticationPlugin"); err != nil {
		fmt.Fprintln(os.Stderr, "extract auth plugin:", err)
		os.Exit(1)
	}

	ams, err := cache.OpenImage(amsImage)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open AppleMediaServices:", err)
		os.Exit(1)
	}

	auth, err := cache.OpenImage(authImage)
	if err != nil {
		fmt.Fprintln(os.Stderr, "open auth plugin:", err)
		os.Exit(1)
	}

	fmt.Printf("FrameworkUUID = %q\n", ams.UUID().String())
	fmt.Printf("PluginUUID = %q\n", auth.UUID().String())
}
