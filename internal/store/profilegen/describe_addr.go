package profilegen

import (
	"context"
	"fmt"

	"github.com/majd/ipatool/v2/internal/sap/assets"
)

// DescribeAddresses reports the nearest symbol for each requested address.
func DescribeAddresses(ctx context.Context, cache *assets.StoreCache, addresses []uint64) error {
	s, err := loadAllSymbols(ctx, cache)
	if err != nil {
		return err
	}

	defer s.close()

	for _, address := range addresses {
		fmt.Printf("%#x => nearest: %s\n", address, s.describe(address))
	}

	return nil
}
