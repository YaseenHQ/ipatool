// Command describeddr reports nearest symbols for guest addresses.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strconv"
	"strings"

	"github.com/majd/ipatool/v2/internal/sap/assets"
	"github.com/majd/ipatool/v2/internal/store/profilegen"
)

func main() {
	addrs := flag.String("addrs", "", "comma-separated hex addresses")
	flag.Parse()

	cache, err := assets.OpenLocalStoreCache(context.Background(), "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer cache.Close()

	var addresses []uint64
	for _, part := range strings.Split(*addrs, ",") {
		part = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(part, "0x"), "0X"))
		if part == "" {
			continue
		}

		value, err := strconv.ParseUint(part, 16, 64)
		if err != nil {
			fmt.Fprintln(os.Stderr, "bad address:", part)
			os.Exit(1)
		}

		addresses = append(addresses, value)
	}

	if err := profilegen.DescribeAddresses(context.Background(), cache, addresses); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
