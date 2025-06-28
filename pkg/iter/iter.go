package bpfilter

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"log"
	"unsafe"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

import "C"

type VmasInfo map[int]*VMAInfo

var vmaIter *link.Iter

type Collection struct {
	VmDumpProgram *ebpf.Program `ebpf:"collect_vmas"`
}

func init() {
	fmt.Println("Loading")

	// Remove memory lock limits required for eBPF
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Printf("Warning: Failed to remove memlock limit: %v", err)
		log.Printf("Continuing anyway, but BPF loading may fail")
	}

	// Load the collection spec first for better error handling
	spec, err := ebpf.LoadCollectionSpec("./task.bpf.o")
	if err != nil {
		log.Fatalf("Failed to load collection spec: %v", err)
	}

	// Load the collection
	var collection Collection
	err = spec.LoadAndAssign(&collection, &ebpf.CollectionOptions{
		Programs: ebpf.ProgramOptions{
			// Add any program-specific options here
		},
	})
	if err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			log.Printf("Failed to verify BPF program:")
			log.Printf("Underlying error: %v", verifierErr.Cause)
			log.Printf("Verifier log (%d lines):", len(verifierErr.Log))
			for i, line := range verifierErr.Log {
				log.Printf("  [%d] %s", i+1, line)
			}
			log.Fatalf("Detailed verifier error: %+v", verifierErr)
		}
		log.Fatalf("Failed to load module: %v", err)
	}

	fmt.Println("Loaded")
	if collection.VmDumpProgram == nil {
		log.Fatal("collect_vmas program not found in collection")
	}

	vmaIter, err = link.AttachIter(link.IterOptions{
		Program: collection.VmDumpProgram,
	})
	if err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			log.Printf("Failed to attach BPF iterator:")
			log.Printf("Underlying error: %v", verifierErr.Cause)
			log.Printf("Verifier log (%d lines):", len(verifierErr.Log))
			for i, line := range verifierErr.Log {
				log.Printf("  [%d] %s", i+1, line)
			}
			log.Fatalf("Detailed verifier error: %+v", verifierErr)
		}
		log.Fatalf("Failed to attach iterator: %v", err)
	}
	fmt.Println("Attached")
}

func VmaDump() (VmasInfo, error) {
	fmt.Println("called dump")

	// Open the iterator to get an io.ReadCloser
	reader, err := vmaIter.Open()
	if err != nil {
		var verifierErr *ebpf.VerifierError
		if errors.As(err, &verifierErr) {
			log.Printf("Failed to open BPF iterator:")
			log.Printf("Underlying error: %v", verifierErr.Cause)
			log.Printf("Verifier log (%d lines):", len(verifierErr.Log))
			for i, line := range verifierErr.Log {
				log.Printf("  [%d] %s", i+1, line)
			}
			return nil, fmt.Errorf("detailed verifier error: %+v", verifierErr)
		}
		return nil, fmt.Errorf("failed to open iterator: %w", err)
	}
	defer reader.Close()

	wholeBuffer := []byte{}
	tempBuf := make([]byte, 1<<20)

	for {
		fmt.Println("Waiting to read from buffer")
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

	infos := VmasInfo{}
	infoSize := int(unsafe.Sizeof(VMAInfo{}))
	fmt.Println("length of buffer:", len(wholeBuffer))
	for i := 0; i < len(wholeBuffer); i += infoSize {
		if i+infoSize <= len(wholeBuffer) {
			infos[i] = (*VMAInfo)(unsafe.Pointer(&wholeBuffer[i]))
		}
	}
	return infos, nil
}

func (p VmasInfo) String() string {
	buf := bytes.Buffer{}
	for _, info := range p {
		buf.WriteString(fmt.Sprintf("PID: %d\n", info.pid))
		buf.WriteString(fmt.Sprintf("Path: %q\n", C.GoString(&info.filepath[0])))
		buf.WriteString(fmt.Sprintf("Start: %x\n", info.start))
		buf.WriteString(fmt.Sprintf("End: %x\n", info.end))
		buf.WriteString(fmt.Sprintf("Flags: %s\n", interpretVMFlags(uint64(info.flags))))
		buf.WriteString(("Hash: "))

		for i := range info.hash {
			buf.WriteString(fmt.Sprintf("%02X", uint8(info.hash[i])))
		}
		buf.WriteString("\n\n\n")

	}
	return buf.String()
}

func interpretVMFlags(flags uint64) string {
	const (
		VM_READ       = 0x00000001
		VM_WRITE      = 0x00000002
		VM_EXEC       = 0x00000004
		VM_SHARED     = 0x00000008
		VM_MAYREAD    = 0x00000010
		VM_MAYWRITE   = 0x00000020
		VM_MAYEXEC    = 0x00000040
		VM_GROWSDOWN  = 0x00000100
		VM_GROWSUP    = 0x00000200
		VM_LOCKED     = 0x00002000
		VM_IO         = 0x00004000
		VM_PFNMAP     = 0x00040000
		VM_DONTEXPAND = 0x00080000
		VM_HUGETLB    = 0x00400000
		VM_MERGEABLE  = 0x10000000
		VM_DONTCOPY   = 0x00020000
		VM_DONTDUMP   = 0x01000000
		VM_ACCOUNT    = 0x02000000
	)

	flagNames := []struct {
		name  string
		value uint64
	}{
		{"VM_READ", VM_READ},
		{"VM_WRITE", VM_WRITE},
		{"VM_EXEC", VM_EXEC},
		{"VM_SHARED", VM_SHARED},
		{"VM_MAYREAD", VM_MAYREAD},
		{"VM_MAYWRITE", VM_MAYWRITE},
		{"VM_MAYEXEC", VM_MAYEXEC},
		{"VM_GROWSDOWN", VM_GROWSDOWN},
		{"VM_GROWSUP", VM_GROWSUP},
		{"VM_LOCKED", VM_LOCKED},
		{"VM_IO", VM_IO},
		{"VM_PFNMAP", VM_PFNMAP},
		{"VM_DONTEXPAND", VM_DONTEXPAND},
		{"VM_HUGETLB", VM_HUGETLB},
		{"VM_MERGEABLE", VM_MERGEABLE},
		{"VM_DONTCOPY", VM_DONTCOPY},
		{"VM_DONTDUMP", VM_DONTDUMP},
		{"VM_ACCOUNT", VM_ACCOUNT},
	}
	result := ""
	for _, f := range flagNames {
		if flags&f.value != 0 {
			result += f.name + " | "
		}
	}

	return result
}
