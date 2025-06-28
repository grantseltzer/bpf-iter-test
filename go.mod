module github.com/grantseltzer/bpf-iter-test

go 1.24.3

require (
	github.com/cilium/ebpf v0.18.0
	github.com/kr/pretty v0.3.1
)

require (
	github.com/kr/text v0.2.0 // indirect
	github.com/rogpeppe/go-internal v1.12.0 // indirect
	golang.org/x/sys v0.30.0 // indirect
)

replace github.com/grantseltzer/bpf-iter-test => ./pkg
