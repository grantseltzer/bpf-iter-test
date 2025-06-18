package bpfilter

import (
	"bytes"
	"fmt"
	"io"
	"log"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
)

type ProcsInfo map[int]*Info

var iter *link.Iter

func init() {
	collection, err := ebpf.LoadCollection("task.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load module: %v", err)
	}
	taskDump, ok := collection.Programs["ps"]
	if !ok {
		log.Fatal("no task dump")
	}
	iter, err = link.AttachIter(link.IterOptions{
		Program: taskDump,
	})
	if err != nil {
		log.Fatalf("Failed to load module: %v", err)
	}
}

func Dump() (ProcsInfo, error) {
	// Open the iterator to get an io.ReadCloser
	reader, err := iter.Open()
	if err != nil {
		log.Fatalf("Failed to open iterator: %v", err)
	}

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

	infos := ProcsInfo{}
	infoSize := int(unsafe.Sizeof(Info{}))
	for i := 0; i < len(wholeBuffer); i += infoSize {
		if i+infoSize <= len(wholeBuffer) {
			info := (*Info)(unsafe.Pointer(&wholeBuffer[i]))
			infos[int(info.pid)] = info
		}
	}
	return infos, nil
}

func (p ProcsInfo) String() string {
	buf := bytes.Buffer{}
	for pid, info := range p {
		buf.WriteString(fmt.Sprintf("PID: %d, PPID: %d, UID: %d, GID: %d, Comm: %s\n", pid, info.ppid, info.uid, info.gid, info.comm))
	}
	return buf.String()
}
