clang -g -O2 -c -target bpf \
  -o task.bpf.o ./bpf/task.bpf.c

go build .

sudo ./bpf-iter-test
