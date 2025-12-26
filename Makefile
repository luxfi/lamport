# Lamport OTS - Makefile

.PHONY: all build test bench clean lint fmt help

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOFMT=gofmt
BINARY_NAME=lamport

all: test build

build:
	$(GOBUILD) -o bin/$(BINARY_NAME) -v .

test:
	$(GOTEST) -v ./...

test-race:
	$(GOTEST) -race -v ./...

bench:
	$(GOTEST) -bench=. -benchmem ./primitives/

coverage:
	$(GOTEST) -coverprofile=coverage.out ./...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html

clean:
	$(GOCMD) clean
	rm -f bin/$(BINARY_NAME)
	rm -f coverage.out coverage.html

lint:
	golangci-lint run ./...

fmt:
	$(GOFMT) -s -w .

tidy:
	$(GOMOD) tidy

deps:
	$(GOGET) -u ./...

# Run the CLI
run:
	$(GOBUILD) -o bin/$(BINARY_NAME) . && ./bin/$(BINARY_NAME) $(ARGS)

# Demo commands
demo-keygen:
	@$(GOBUILD) -o bin/$(BINARY_NAME) . && ./bin/$(BINARY_NAME) keygen

demo-chain:
	@$(GOBUILD) -o bin/$(BINARY_NAME) . && ./bin/$(BINARY_NAME) chain 10

demo-threshold:
	@$(GOBUILD) -o bin/$(BINARY_NAME) . && ./bin/$(BINARY_NAME) threshold 3 5

demo-benchmark:
	@$(GOBUILD) -o bin/$(BINARY_NAME) . && ./bin/$(BINARY_NAME) benchmark

# Fuzz testing
fuzz:
	$(GOTEST) -fuzz=FuzzSignVerify -fuzztime=30s ./primitives/

help:
	@echo "Lamport OTS - Post-Quantum One-Time Signatures"
	@echo ""
	@echo "Targets:"
	@echo "  build           Build the CLI binary"
	@echo "  test            Run all tests"
	@echo "  test-race       Run tests with race detector"
	@echo "  bench           Run benchmarks"
	@echo "  coverage        Generate coverage report"
	@echo "  lint            Run linter"
	@echo "  fmt             Format code"
	@echo "  tidy            Tidy go.mod"
	@echo "  clean           Clean build artifacts"
	@echo ""
	@echo "Demo targets:"
	@echo "  demo-keygen     Generate a key pair"
	@echo "  demo-chain      Generate a key chain"
	@echo "  demo-threshold  Demo threshold signing"
	@echo "  demo-benchmark  Run benchmarks"
	@echo ""
	@echo "Fuzz testing:"
	@echo "  fuzz            Run fuzz tests (30s)"
