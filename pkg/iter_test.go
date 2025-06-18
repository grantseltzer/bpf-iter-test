package bpfilter

import (
	"os"
	"os/exec"
	"testing"
	"time"
)

func BenchmarkDump(b *testing.B) {
	b.Run("250", func(b *testing.B) {
		benchmarkDump(250, b)
	})
	b.Run("10_000", func(b *testing.B) {
		benchmarkDump(10_000, b)
	})
}

// BenchmarkDump measures the performance of the Dump() function
func benchmarkDump(numProcs int, b *testing.B) {
	processes := make([]*os.Process, 0, numProcs)

	// Fork processes using a simple command that will sleep
	for i := 0; i < numProcs; i++ {
		cmd := exec.Command("sleep", "3600") // Sleep for 1 hour
		cmd.Start()
		processes = append(processes, cmd.Process)
	}
	// Ensure cleanup happens even if test fails
	defer func() {
		for _, proc := range processes {
			if proc != nil {
				proc.Kill() // Force kill all processes
				proc.Wait()
			}
		}
	}()

	// Wait a bit for processes to start
	time.Sleep(100 * time.Millisecond)

	// Reset timer to exclude any setup time
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		infos, err := Dump()
		if err != nil {
			b.Fatalf("Dump() failed: %v", err)
		}

		// Ensure the result is not optimized away
		if len(infos) == 0 {
			b.Log("Warning: Dump() returned empty result")
		}
	}
	b.StopTimer()
	b.Log("Number of procs:", len(processes))
}
