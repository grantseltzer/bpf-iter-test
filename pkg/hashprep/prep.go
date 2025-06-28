package hashprep

import (
	"crypto/sha256"
	"debug/elf"
	"fmt"
	"log"
)

const PageSize = 4096

type Range struct {
	Path  string
	Start uint64
	End   uint64
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
		// // Check if section is executable
		// if section.Flags&elf.SHF_EXECINSTR == 0 {
		// 	continue
		// }

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
