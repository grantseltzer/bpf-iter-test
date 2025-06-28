# Variables
BPF_OBJECT := task.bpf.o
BPF_SOURCE := ./bpf/task.bpf.c
BINARY := bpf-iter-test
GO_MODULE := github.com/grantseltzer/bpf-iter-test

# Default target
.PHONY: all
all: build

# Build the BPF object file
.PHONY: bpf
bpf: $(BPF_OBJECT)

$(BPF_OBJECT): $(BPF_SOURCE)
	@echo "Building BPF program..."
	clang -g -O2 -c -target bpf \
		-o $(BPF_OBJECT) $(BPF_SOURCE)

# Build the Go binary
.PHONY: build
build: bpf
	@echo "Building Go binary..."
	go build .

# Run the program with sudo
.PHONY: run
run: build
	@echo "Running BPF program (requires sudo)..."
	sudo ./$(BINARY)

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning build artifacts..."
	rm -f $(BPF_OBJECT) $(BINARY)

# Install Go dependencies
.PHONY: deps
deps:
	@echo "Installing Go dependencies..."
	go mod download

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test ./...

# Run benchmarks
.PHONY: benchmark
benchmark:
	@echo "Running benchmarks..."
	go test -bench=. ./...

# Format Go code
.PHONY: fmt
fmt:
	@echo "Formatting Go code..."
	go fmt ./...

# Run linter
.PHONY: lint
lint:
	@echo "Running linter..."
	go vet ./...

# Build and run without sudo (will show permission errors)
.PHONY: debug
debug: build
	@echo "Running BPF program (will show permission errors if not run as root)..."
	./$(BINARY)

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  all       - Build everything (default)"
	@echo "  bpf       - Build BPF object file only"
	@echo "  build     - Build both BPF program and Go binary"
	@echo "  run       - Build and run with sudo (requires root)"
	@echo "  debug     - Build and run without sudo (shows permission errors)"
	@echo "  clean     - Remove build artifacts"
	@echo "  deps      - Install Go dependencies"
	@echo "  test      - Run Go tests"
	@echo "  benchmark - Run Go benchmarks"
	@echo "  fmt       - Format Go code"
	@echo "  lint      - Run Go linter"
	@echo "  help      - Show this help message"
