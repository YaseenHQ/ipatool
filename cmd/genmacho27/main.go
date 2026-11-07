// Command genmacho27 regenerates the SAP shared-cache address maps from the
// extracted macOS AppleMediaServices image.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/majd/ipatool/v2/internal/sap/assets"
	"github.com/majd/ipatool/v2/internal/store/profilegen"
)

func main() {
	imagePath := flag.String("image", "/private/var/folders/nr/bm_3v8510zv5vv6fgfjfx7q00000gn/T/opencode/extracted/AppleMediaServices", "extracted AppleMediaServices Mach-O")
	flag.Parse()

	cache, err := assets.OpenLocalStoreCache(context.Background(), "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer cache.Close()

	if err := profilegen.GenerateMachineMaps(context.Background(), cache, *imagePath); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
