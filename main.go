package main

import (
	"fmt"
	"log"

	bpfiter "github.com/grantseltzer/bpf-iter-test/pkg"
)

func main() {
	infos, err := bpfiter.Dump()
	if err != nil {
		log.Fatalf("Failed to dump: %v", err)
	}
	fmt.Println(infos.String())
}
