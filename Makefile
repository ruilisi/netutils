# Project metadata
BINARY_NAME := netutils
PKG := ./...
GO := go

# Default target
.PHONY: all
all: build

## Build the binary
.PHONY: build
build:
	$(GO) build -o bin/$(BINARY_NAME) .

## Run tests
.PHONY: test
test:
	$(GO) test $(PKG)

## Run tests with verbose output
.PHONY: test-v
test-v:
	$(GO) test -v $(PKG)

## Run tests with race detector
.PHONY: test-race
test-race:
	$(GO) test -race $(PKG)

## Run short tests only
.PHONY: test-short
test-short:
	$(GO) test -short $(PKG)

## Run tests with CGO enabled
.PHONY: test-cgo
test-cgo:
	CGO_ENABLED=1 $(GO) test $(PKG)

## Run tests with CGO enabled (verbose)
.PHONY: test-cgo-v
test-cgo-v:
	CGO_ENABLED=1 $(GO) test -v $(PKG)

## Run tests with coverage report
.PHONY: test-cover
test-cover:
	$(GO) test -cover $(PKG)

## Generate HTML coverage report
.PHONY: test-cover-html
test-cover-html:
	$(GO) test -coverprofile=coverage.out $(PKG)
	$(GO) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

## Run all benchmarks
.PHONY: bench
bench:
	$(GO) test -bench=. -run=^$$ $(PKG)

## Run benchmarks with memory stats
.PHONY: bench-mem
bench-mem:
	$(GO) test -bench=. -benchmem -run=^$$ $(PKG)

## Run benchmarks multiple times for stable results
.PHONY: bench-count
bench-count:
	$(GO) test -bench=. -benchmem -count=5 -run=^$$ $(PKG)

## Save benchmark results to file (for comparison with benchstat)
.PHONY: bench-save
bench-save:
	$(GO) test -bench=. -benchmem -count=10 -run=^$$ $(PKG) > bench.txt
	@echo "Benchmark results saved to bench.txt"

## Run benchmarks with CPU profile
.PHONY: bench-cpu
bench-cpu:
	$(GO) test -bench=. -cpuprofile=cpu.out -run=^$$ $(PKG)
	@echo "CPU profile: cpu.out (view with: go tool pprof cpu.out)"

## Run benchmarks with memory profile
.PHONY: bench-mem-profile
bench-mem-profile:
	$(GO) test -bench=. -memprofile=mem.out -run=^$$ $(PKG)
	@echo "Memory profile: mem.out (view with: go tool pprof mem.out)"

## Run all checks (fmt, vet, lint, test)
.PHONY: check
check: fmt vet lint test

## Format source code
.PHONY: fmt
fmt:
	$(GO) fmt $(PKG)

## Run go vet
.PHONY: vet
vet:
	$(GO) vet $(PKG)

## Clean build output and generated files
.PHONY: clean
clean:
	rm -rf bin/
	rm -f coverage.out coverage.html
	rm -f cpu.out mem.out bench.txt

## Tidy up go.mod and go.sum
.PHONY: tidy
tidy:
	$(GO) mod tidy

## Download dependencies
.PHONY: deps
deps:
	$(GO) mod download

## Install the binary to $GOBIN
.PHONY: install
install:
	$(GO) install .

## Lint (optional, needs golangci-lint)
.PHONY: lint
lint:
	golangci-lint run

## Run the app
.PHONY: run
run:
	$(GO) run .

## Help
.PHONY: help
help:
	@echo "make [target]"
	@echo ""
	@echo "Build:"
	@echo "  build            - Build the project"
	@echo "  install          - Install binary to GOBIN"
	@echo "  run              - Run the app"
	@echo "  clean            - Remove build files"
	@echo ""
	@echo "Test:"
	@echo "  test             - Run tests"
	@echo "  test-v           - Run tests (verbose)"
	@echo "  test-race        - Run tests with race detector"
	@echo "  test-short       - Run short tests only"
	@echo "  test-cgo         - Run tests with CGO enabled"
	@echo "  test-cgo-v       - Run tests with CGO enabled (verbose)"
	@echo "  test-cover       - Run tests with coverage"
	@echo "  test-cover-html  - Generate HTML coverage report"
	@echo ""
	@echo "Benchmark:"
	@echo "  bench            - Run all benchmarks"
	@echo "  bench-mem        - Run benchmarks with memory stats"
	@echo "  bench-count      - Run benchmarks 5x for stable results"
	@echo "  bench-save       - Save benchmark results to bench.txt"
	@echo "  bench-cpu        - Run benchmarks with CPU profile"
	@echo "  bench-mem-profile - Run benchmarks with memory profile"
	@echo ""
	@echo "Code Quality:"
	@echo "  fmt              - Format code"
	@echo "  vet              - Run go vet"
	@echo "  lint             - Run linter (needs golangci-lint)"
	@echo "  check            - Run fmt, vet, lint, and test"
	@echo ""
	@echo "Dependencies:"
	@echo "  tidy             - Clean up go.mod/go.sum"
	@echo "  deps             - Download dependencies"

