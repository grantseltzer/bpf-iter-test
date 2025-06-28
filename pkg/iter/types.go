package bpfilter

// #define CGO
// #include "../../bpf/types.h"
import "C"

type VMAInfo C.vma_info_t

//
