package hashprep

import (
	"fmt"
	"testing"
)

func TestPrepareHashes(t *testing.T) {
	hashes, err := PrepareHashes("testdata/bpf-iter-test")
	if err != nil {
		t.Fatalf("PrepareHashes() failed: %v", err)
	}
	for k, v := range hashes {
		fmt.Printf("%#v\t", k)
		for i := range v {
			fmt.Printf("%02X", v[i])
		}
		fmt.Println()
	}
}

func TestParseDynamicEntries(t *testing.T) {
	err := parseDynamicEntries("testdata/bpf-iter-test")
	if err != nil {
		t.Fatalf("parseDynamicEntries() failed: %v", err)
	}
}
