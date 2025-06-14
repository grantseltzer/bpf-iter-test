package main

import (
	"log"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {

	collection, err := ebpf.LoadCollection("task.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load module: %v", err)
	}

	taskDump, ok := collection.Programs["dump_task"]
	if !ok {
		log.Fatal("no task dump")
	}

	iter, err := link.AttachIter(link.IterOptions{
		Program: taskDump,
	})
	if err != nil {
		log.Fatalf("Failed to load module: %v", err)
	}

	err = iter.Pin("/sys/fs/bpf/foobar")
	if err != nil {
		log.Fatalf("Failed to load module: %v", err)
	}

	// Create a channel to listen for Ctrl-C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)

	// Wait for Ctrl-C
	<-sig

	// Clean up
	iter.Close()
	collection.Close()
}
