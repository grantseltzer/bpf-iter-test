package main

import (
	"fmt"
	"log"

	bpfiter "github.com/grantseltzer/bpf-iter-test/pkg/iter"
)

func main() {
	infos, err := bpfiter.VmaDump()
	if err != nil {
		log.Fatalf("Failed to dump: %v", err)
	}
	fmt.Println(infos.String())
}
