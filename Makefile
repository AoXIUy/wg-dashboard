.PHONY: all build build-linux-amd64 build-linux-arm64 build-windows test bench clean help

APP_NAME := wg-dashboard
VERSION ?= $(shell git describe --tags --always 2>/dev/null || echo "v2.0.0")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_DATE ?= $(shell date -u +'%Y-%m-%dT%H:%M:%SZ' 2>/dev/null || echo "unknown")

LDFLAGS := -s -w \
	-X main.Version=$(VERSION) \
	-X main.GitCommit=$(COMMIT) \
	-X main.BuildDate=$(BUILD_DATE)

all: test build

build:
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(APP_NAME) .

build-linux-amd64:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(APP_NAME)-linux-amd64 .

build-linux-arm64:
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(APP_NAME)-linux-arm64 .

build-windows:
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(APP_NAME).exe .

test:
	CGO_ENABLED=0 go test -v ./...

bench:
	CGO_ENABLED=0 go test -bench=. -benchmem ./...

clean:
	rm -rf bin/ .sandbox_data/

help:
	@echo "WireGuard Pro Dashboard Build Targets:"
	@echo "  make build              - Build single binary for current OS (pure Go, CGO_ENABLED=0)"
	@echo "  make build-linux-amd64  - Cross-compile for Linux AMD64"
	@echo "  make build-linux-arm64  - Cross-compile for Linux ARM64"
	@echo "  make build-windows      - Cross-compile for Windows AMD64"
	@echo "  make test               - Run all unit and integration tests"
	@echo "  make bench              - Run performance benchmarks"
	@echo "  make clean              - Clean build artifacts and sandboxes"
