# Build the forensic CLI with an auto-incrementing, git-derived version.
#
# The version is BASE.<commit-count>+g<short-hash>[-dirty], e.g. 0.1.7+g20abf71.
# The commit count increments on every commit, so the version rises on every
# push without any manual bump. A plain `go build` (no ldflags) keeps the
# in-code default instead.

BINARY := forensic
PKG    := ./cmd/forensic
BINDIR := bin

BASE    := 0.1
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
COUNT   := $(shell git rev-list --count HEAD 2>/dev/null || echo 0)
DIRTY   := $(shell test -n "$$(git status --porcelain 2>/dev/null)" && echo -dirty)
VERSION := $(BASE).$(COUNT)+g$(COMMIT)$(DIRTY)
LDFLAGS := -X main.version=$(VERSION)

.PHONY: all build install test vet fmt version clean

all: build

## build: compile the versioned binary into ./bin
build:
	@mkdir -p $(BINDIR)
	go build -ldflags "$(LDFLAGS)" -o $(BINDIR)/$(BINARY) $(PKG)

## install: install the versioned binary into $GOBIN/$GOPATH/bin
install:
	go install -ldflags "$(LDFLAGS)" $(PKG)

## test: run the test suite
test:
	go test ./...

## vet: run go vet
vet:
	go vet ./...

## fmt: format all sources
fmt:
	gofmt -w .

## version: print the version that would be baked in
version:
	@echo $(VERSION)

## clean: remove build artifacts
clean:
	rm -rf $(BINDIR)
