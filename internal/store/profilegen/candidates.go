package profilegen

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/majd/ipatool/v2/internal/sap/assets"
)

// loadAllSymbols loads every shared-cache image and its symbol table.
func loadAllSymbols(ctx context.Context, cache *assets.StoreCache) (*source, error) {
	s, err := newSource(ctx, cache)
	if err != nil {
		return nil, err
	}

	images, err := cache.Images()
	if err != nil {
		s.close()

		return nil, fmt.Errorf("list cache images: %w", err)
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

	return s, nil
}

// CandidateAddresses returns every shared-cache address whose symbol name
// matches name, ignoring leading underscores. The result is sorted so repeated
// runs are deterministic.
func CandidateAddresses(ctx context.Context, cache *assets.StoreCache, name string) ([]uint64, error) {
	s, err := loadAllSymbols(ctx, cache)
	if err != nil {
		return nil, err
	}

	defer s.close()

	want := strings.TrimLeft(name, "_")

	var out []uint64

	for address, symbol := range s.symbols {
		if strings.TrimLeft(symbol, "_") == want {
			out = append(out, address)
		}
	}

	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })

	return out, nil
}
