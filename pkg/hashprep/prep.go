package hashprep

import (
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"fmt"
	"log"
)

const PageSize = 4096
const DynamicEntrySize = 16 // (assuming ELFCLASS64)

type Range struct {
	Path  string
	Start uint64
	End   uint64
}

func parseDynamicEntries(bin string) error {
	elfFile, err := elf.Open(bin)
	if err != nil {
		return fmt.Errorf("failed to open ELF file: %w", err)
	}
	defer elfFile.Close()

	dynamicSection := elfFile.Section(".dynamic")
	if dynamicSection == nil {
		return fmt.Errorf("failed to get dynamic section")
	}
	dynamicData, err := dynamicSection.Data()
	if err != nil {
		return fmt.Errorf("failed to get dynamic data: %w", err)
	}

	for i := range dynamicData {
		if i+DynamicEntrySize > len(dynamicData) {
			break
		}
		tag := elf.DynTag(binary.LittleEndian.Uint64(dynamicData[i : i+8]))
		val := binary.LittleEndian.Uint64(dynamicData[i+8 : i+16])
		fmt.Printf("Tag: %s, Val: %d\n", tag, val)
	}
	return nil
}

func PrepareHashes(bin string) (map[Range][32]byte, error) {
	// Read all executable sections of the binary
	// and split into ranges of 4096 (for now, only page size we'll support)
	// hash each range and store in a map (key: struct{start: uint64, end: uint64}, value: hash)
	// return the map

	hashes := make(map[Range][32]byte)

	// Open the ELF file
	elfFile, err := elf.Open(bin)
	if err != nil {
		return nil, fmt.Errorf("failed to open ELF file: %w", err)
	}
	defer elfFile.Close()

	// Iterate through all sections
	for _, section := range elfFile.Sections {

		// Read the section data
		data, err := section.Data()
		if err != nil {
			log.Printf("Warning: failed to read section %s: %v", section.Name, err)
			continue
		}

		// Get the virtual address of the section
		vaddr := section.Addr

		// Split into page-sized chunks and hash each
		for offset := uint64(0); offset < uint64(len(data)); offset += PageSize {
			start := vaddr + offset
			end := start + PageSize

			// Get the chunk of data for this page
			chunkEnd := offset + PageSize
			if chunkEnd > uint64(len(data)) {
				chunkEnd = uint64(len(data))
				end = vaddr + chunkEnd
			}
			chunk := data[offset:chunkEnd]

			// If chunk is smaller than page size, pad with zeros
			if len(chunk) < PageSize {
				padded := make([]byte, PageSize)
				copy(padded, chunk)
				chunk = padded
			}

			// Hash the chunk
			hash := sha256.Sum256(chunk)

			// Store in map
			r := Range{Path: bin, Start: start, End: end}
			hashes[r] = hash
		}
	}

	return hashes, nil
}
