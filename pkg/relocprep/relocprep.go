package relocprep

import "debug/elf"

// DynamicEntry represents a parsed entry from the .dynamic section
type DynamicEntry struct {
	Tag elf.DynTag
	Val uint64
}

// ParseDynamicEntries parses the dynamic entries from the ELF file
func ParseDynamicEntries(elfFile *elf.File, dynamicData []byte) ([]DynamicEntry, error) {
	var entries []DynamicEntry

	// Determine byte order
	byteOrder := elfFile.ByteOrder

	// Size of each entry depends on the ELF class
	var entrySize int
	if elfFile.Class == elf.ELFCLASS64 {
		entrySize = 16 // 8 bytes for tag + 8 bytes for value
	} else {
		entrySize = 8 // 4 bytes for tag + 4 bytes for value
	}

	// Parse each dynamic entry
	for i := 0; i < len(dynamicData); i += entrySize {
		if i+entrySize > len(dynamicData) {
			break
		}

		var tag elf.DynTag
		var val uint64

		if elfFile.Class == elf.ELFCLASS64 {
			tag = elf.DynTag(byteOrder.Uint64(dynamicData[i : i+8]))
			val = byteOrder.Uint64(dynamicData[i+8 : i+16])
		} else {
			tag = elf.DynTag(byteOrder.Uint32(dynamicData[i : i+4]))
			val = uint64(byteOrder.Uint32(dynamicData[i+4 : i+8]))
		}

		// DT_NULL marks the end of the dynamic array
		if tag == elf.DT_NULL {
			break
		}

		entries = append(entries, DynamicEntry{Tag: tag, Val: val})
	}

	return entries, nil
}
