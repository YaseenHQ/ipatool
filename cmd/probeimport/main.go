// Command probeimport reports new shared-cache addresses for requested symbols.
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
	names := flag.String("names", "CRIsAutoSubmitEnabled", "comma-separated symbol names")
	flag.Parse()

	cache, err := assets.OpenLocalStoreCache(context.Background(), "/System/Volumes/Preboot/Cryptexes/OS/System/Library/dyld/dyld_shared_cache_arm64e")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	defer cache.Close()

	found, err := profilegen.ProbeImportAddresses(context.Background(), cache, splitNames(*names))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	for _, name := range splitNames(*names) {
		if address, ok := found[name]; ok {
			fmt.Printf("%s = %#x\n", name, address)
		} else {
			fmt.Printf("%s = NOT FOUND\n", name)
		}
	}
}

func splitNames(value string) []string {
	var result []string
	current := ""
	for _, r := range value {
		if r == ',' {
			if current != "" {
				result = append(result, current)
			}
			current = ""
			continue
		}
		current += string(r)
	}
	if current != "" {
		result = append(result, current)
	}
	return result
}
