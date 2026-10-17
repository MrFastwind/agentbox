GO ?= go
COVER_PROFILE ?= coverall.out

.PHONY: build vet test test-race cover cover-check fmt lint clean

build:
	$(GO) build ./...

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
