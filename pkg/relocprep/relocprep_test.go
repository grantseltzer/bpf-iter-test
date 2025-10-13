package relocprep

import (
	"debug/elf"
	"fmt"
	"testing"
)

func TestParseDynamicEntries(t *testing.T) {
	elfFile, err := elf.Open("../../testdata/bpf-iter-test")
	if err != nil {
		t.Fatalf("failed to open ELF file: %v", err)
	}
	defer elfFile.Close()

	dynamicData, err := elfFile.Section(".dynamic").Data()
	if err != nil {
		t.Fatalf("failed to get dynamic data: %v", err)
	}

	entries, err := ParseDynamicEntries(elfFile, dynamicData)
	if err != nil {
		t.Fatalf("failed to parse dynamic entries: %v", err)
	}

	for _, entry := range entries {
		fmt.Printf("Tag: %s, Val: %d\n", entry.Tag, entry.Val)
	}
}
