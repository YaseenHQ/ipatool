package profilegen

import (
	"context"
	"fmt"
	"os"
	"strings"

	"github.com/majd/ipatool/v2/internal/sap/assets"
)

// DescribeAddresses reports the nearest symbol for each requested address.
func DescribeAddresses(ctx context.Context, cache *assets.StoreCache, addresses []uint64) error {
	s, err := newSource(ctx, cache)
	if err != nil {
		return err
	}

	defer s.close()

	images, err := cache.Images()
	if err != nil {
		return fmt.Errorf("list cache images: %w", err)
	}

	for name := range images {
		if _, ok := s.images[name]; !ok {
			_ = s.loadImage(name)
		}
	}

	for name := range s.images {
		if !s.symbolsLoaded[name] {
			loadSymbolsSafe(s, s.images[name])
			s.symbolsLoaded[name] = true
		}
	}

	fmt.Fprintf(os.Stderr, "loaded %d images, %d symbols\n", len(s.images), len(s.symbols))

	for _, address := range addresses {
		image := ""
		for candidate := range s.images {
			f := s.images[candidate]
			for _, seg := range f.Segments() {
				if address >= seg.Addr && address < seg.Addr+seg.Memsz {
					image = candidate

					break
				}
			}

			if image != "" {
				break
			}
		}

		fmt.Printf("%#x => image: %s | nearest: %s\n", address, image, s.describe(address))
	}

	_ = strings.TrimSpace("")

	return nil
}
