// Command probemetadata decodes the committed Store profile and prints its metadata summary.
package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"

	"github.com/majd/ipatool/v2/internal/store/profile"
)

func main() {
	data, err := profile.Load(context.Background())
	if err != nil {
		fmt.Fprintln(os.Stderr, "load profile:", err)
		os.Exit(1)
	}

	var meta struct {
		UUID      string `json:"uuid"`
		PluginUUID string `json:"pluginUUID"`
		Calls     []struct {
			Address uint64 `json:"address"`
			Symbol  string `json:"symbol"`
		} `json:"calls"`
	}

	if err := json.Unmarshal(data.Metadata, &meta); err != nil {
		fmt.Fprintln(os.Stderr, "decode metadata:", err)
		os.Exit(1)
	}

	fmt.Println("uuid:", meta.UUID)
	fmt.Println("pluginUUID:", meta.PluginUUID)
	fmt.Println("calls:", len(meta.Calls))
	for _, call := range meta.Calls {
		found := ""
		if call.Symbol == "CRIsAutoSubmitEnabled" {
			found = "  <-- CRIsAutoSubmitEnabled present"
		}
		fmt.Printf("  %#x %s%s\n", call.Address, call.Symbol, found)
	}
}
