.PHONY: build test clean install run help

# Binary name
BINARY_NAME=certgen
BINARY_PATH=./cmd/certgen

# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOTEST=$(GOCMD) test
GOGET=$(GOCMD) get
GOMOD=$(GOCMD) mod
GOVET=$(GOCMD) vet
GOFMT=$(GOCMD) fmt

# Build flags
LDFLAGS=-ldflags "-w -s"

# Default target
all: test build

## help: Show this help message
help:
	@echo "Usage: make [target]"
	@echo ""
	@echo "Targets:"
	@grep -E '^##' Makefile | sed -e 's/## /  /'

## build: Build the binary
build:
	$(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME) $(BINARY_PATH)

## test: Run unit tests
test:
	$(GOTEST) -v ./pkg/... ./tests/...

## test-race: Run tests with race detector
test-race:
	$(GOTEST) -race -v ./pkg/... ./tests/...

## test-coverage: Run tests with coverage
test-coverage:
	$(GOTEST) -v -coverpkg=./pkg/... -coverprofile=coverage.out ./tests/...
	$(GOCMD) tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

## test-coverage-report: Show coverage report in terminal
test-coverage-report:
	$(GOTEST) -v -coverpkg=./pkg/... -coverprofile=coverage.out ./tests/...
	$(GOCMD) tool cover -func=coverage.out

## clean: Remove binary and test artifacts
clean:
	rm -f $(BINARY_NAME)
	rm -f *_rootCA.* *_leaf.* *_certs.p12 *_base64.txt
	rm -f coverage.out coverage.html
	$(GOCMD) clean

## install: Install the binary to $GOPATH/bin
install:
	$(GOBUILD) -o $(GOPATH)/bin/$(BINARY_NAME) $(BINARY_PATH)

## fmt: Format the code
fmt:
	$(GOFMT) ./...

## vet: Run go vet
vet:
	$(GOVET) ./...

## lint: Run golangci-lint (requires golangci-lint to be installed)
lint:
	golangci-lint run

## deps: Download dependencies
deps:
	$(GOMOD) download

## tidy: Clean up dependencies
tidy:
	$(GOMOD) tidy

## run: Build and run with example domain
run: build
	./$(BINARY_NAME) --domain example.local

## test-all: Run all tests and checks
test-all: fmt vet test-race

## release: Build release binaries for multiple platforms
release:
	GOOS=linux GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-linux-amd64 $(BINARY_PATH)
	GOOS=darwin GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-darwin-amd64 $(BINARY_PATH)
	GOOS=darwin GOARCH=arm64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-darwin-arm64 $(BINARY_PATH)
	GOOS=windows GOARCH=amd64 $(GOBUILD) $(LDFLAGS) -o $(BINARY_NAME)-windows-amd64.exe $(BINARY_PATH)
	@echo "Generating checksums..."
	@sha256sum $(BINARY_NAME)-* > checksums.txt