// Command findslots maps every GOT slot in an extracted AppleMediaServices
// image to the symbol it imports, using the indirect symbol table. Local
// debugging aid; not part of normal builds.
package main

import (
	"bytes"
	"flag"
	"fmt"
	"os"

	"github.com/blacktop/go-macho"
)

func main() {
	imagePath := flag.String("image", "/private/var/folders/nr/bm_3v8510zv5vv6fgfjfx7q00000gn/T/opencode/extracted/AppleMediaServices", "extracted AppleMediaServices Mach-O")
	flag.Parse()

	data, err := os.ReadFile(*imagePath)
	if err != nil {
		fmt.Fprintln(os.Stderr, "read image:", err)
		os.Exit(1)
	}

	file, err := macho.NewFile(bytes.NewReader(data))
	if err != nil {
		fmt.Fprintln(os.Stderr, "parse image:", err)
		os.Exit(1)
	}

	if file.Dysymtab == nil || file.Symtab == nil {
		fmt.Fprintln(os.Stderr, "image has no symbol or dynamic symbol table")
		os.Exit(1)
	}

	const indirectSymbolLocal = 0x80000000
	const indirectSymbolAbs = 0x40000000

	for _, sec := range file.Sections {
		if sec.Name != "__got" && sec.Name != "__auth_got" {
			continue
		}

		for i := uint64(0); i+8 <= sec.Size; i += 8 {
			idx := uint64(sec.Reserved1) + i/8
			if idx >= uint64(len(file.Dysymtab.IndirectSyms)) {
				break
			}

			symIdx := file.Dysymtab.IndirectSyms[idx]
			if symIdx&(indirectSymbolLocal|indirectSymbolAbs) != 0 || int(symIdx) >= len(file.Symtab.Syms) {
				fmt.Printf("%s %#x <unbound>\n", sec.Name, sec.Addr+i)

				continue
			}

			fmt.Printf("%s %#x %s\n", sec.Name, sec.Addr+i, file.Symtab.Syms[symIdx].Name)
		}
	}
}
