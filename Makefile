GO ?= go
COVER_PROFILE ?= coverall.out

# Install location for `make install`. PREFIX is the usual knob; DESTDIR is the
# staging root packaging tools set, never a user-facing option.
PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
INSTALL ?= install

# The version baked into the binary, taken from the same default the release
# workflow reads so `agentbox version` is honest for a local install.
VERSION ?= $(shell sed -n 's/.*var version = "\(.*\)".*/\1/p' cmd/main.go)
LDFLAGS ?= -s -w -X agentbox/cmd.version=$(VERSION)

.PHONY: build agentbox vet test test-race cover cover-check fmt lint install uninstall clean

build:
	$(GO) build ./...

# The distribution unit: one static binary with the Containerfiles and the
# seccomp profile compiled in, so nothing else is installed beside it.
agentbox:
	$(GO) build -trimpath -ldflags="$(LDFLAGS)" -o agentbox .

install: agentbox
	$(INSTALL) -d $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 0755 agentbox $(DESTDIR)$(BINDIR)/agentbox

uninstall:
	rm -f $(DESTDIR)$(BINDIR)/agentbox

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

test-race:
	$(GO) test -race ./...

# Cross-package coverage: -coverpkg=./... counts code exercised by tests that
# live in a different package (notably internal/fsx, exercised by policy tests).
cover:
	$(GO) test ./... -coverpkg=./... -coverprofile=$(COVER_PROFILE)
	@$(GO) tool cover -func=$(COVER_PROFILE) | tail -1

cover-check: cover
	./scripts/coverage-gate.sh

fmt:
	gofmt -w .

lint: vet
	@unformatted=$$(gofmt -l .); \
	if [ -n "$$unformatted" ]; then echo "gofmt needed on:"; echo "$$unformatted"; exit 1; fi

clean:
	rm -f $(COVER_PROFILE) coverage.out
	$(GO) clean ./...
