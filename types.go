package main

// #define CGO
// #include "./bpf/types.h"
import "C"

type Info C.info_t
