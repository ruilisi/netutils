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
	$(GO) test -v $(PKG)

## Format source code
.PHONY: fmt
fmt:
	$(GO) fmt $(PKG)

## Run go vet
.PHONY: vet
vet:
	$(GO) vet $(PKG)

## Clean build output
.PHONY: clean
clean:
	rm -rf bin/

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
	@echo "  build   - Build the project"
	@echo "  test    - Run tests"
	@echo "  fmt     - Format code"
	@echo "  vet     - Run go vet"
	@echo "  tidy    - Clean up go.mod/go.sum"
	@echo "  deps    - Download dependencies"
	@echo "  install - Install binary"
	@echo "  run     - Run the app"
	@echo "  clean   - Remove build files"
	@echo "  lint    - Run linter (needs golangci-lint)"

