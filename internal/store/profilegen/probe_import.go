package profilegen

import (
	"context"

	"github.com/majd/ipatool/v2/internal/sap/assets"
)

// ProbeImportAddresses scans the Store images' data sections for shared-cache
// pointers and reports resolved symbol addresses matching the requested names.
func ProbeImportAddresses(ctx context.Context, cache *assets.StoreCache, want []string) (map[string]uint64, error) {
	s, err := newSource(ctx, cache)
	if err != nil {
		return nil, err
	}

	defer s.close()

	wanted := map[string]bool{}
	for _, name := range want {
		wanted[name] = true
	}

	found := map[string]uint64{}

	for _, image := range []string{amsImage, authImage} {
		f := s.images[image]
		if f == nil {
			continue
		}

		for _, seg := range f.Segments() {
			if seg.Name == "__TEXT" || seg.Name == "__LINKEDIT" || seg.Memsz < 8 {
				continue
			}

			for offset := uint64(0); offset+8 <= seg.Memsz; offset += 8 {
				value := s.u64(seg.Addr + offset)
				if value == 0 {
					continue
				}

				name := s.symbol(value)
				if wanted[name] {
					found[name] = value
				}
			}
		}
	}

	return found, nil
}
