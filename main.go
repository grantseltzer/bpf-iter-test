package main

import (
	"fmt"
	"io"
	"log"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

func main() {
	collection, err := ebpf.LoadCollection("task.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load module: %v", err)
	}
	taskDump, ok := collection.Programs["ps"]
	if !ok {
		log.Fatal("no task dump")
	}
	iter, err := link.AttachIter(link.IterOptions{
		Program: taskDump,
	})
	if err != nil {
		log.Fatalf("Failed to load module: %v", err)
	}

	// Open the iterator to get an io.ReadCloser
	reader, err := iter.Open()
	if err != nil {
		log.Fatalf("Failed to open iterator: %v", err)
	}
	defer reader.Close()

	wholeBuffer := []byte{}
	tempBuf := make([]byte, 1024)

	for {
		n, err := reader.Read(tempBuf)
		if err != nil && err != io.EOF {
			log.Printf("Failed to read: %v", err)
			break
		}
		if err == io.EOF {
			break
		}
		wholeBuffer = append(wholeBuffer, tempBuf[:n]...)
	}

	infoSize := int(unsafe.Sizeof(Info{}))
	for i := 0; i < len(wholeBuffer); i += infoSize {
		if i+infoSize <= len(wholeBuffer) {
			info := (*Info)(unsafe.Pointer(&wholeBuffer[i]))
			fmt.Printf("PID: %d, PPID: %d, UID: %d, GID: %d, Comm: %s\n", info.pid, info.ppid, info.uid, info.gid, info.comm)
		}
	}

	// Clean up
	iter.Close()
	collection.Close()
}
