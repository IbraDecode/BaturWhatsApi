GO      ?= go
BIN     := bin
LDFLAGS := -s -w
FUZZTIME ?= 5s

.PHONY: all build test race vet fmt fmt-check bench demo doctor fuzz clean lint cross

all: vet test build

build:
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/batur ./cmd/batur

test:
	$(GO) test ./... -count=1

race:
	$(GO) test ./... -count=1 -race -timeout 30m

vet:
	$(GO) vet ./...

fmt:
	$(GO) fmt ./...

fmt-check:
	@out=$$(gofmt -l . | grep -v '^$$' || true); \
	if [ -n "$$out" ]; then echo "unformatted files:"; echo "$$out"; exit 1; fi

bench:
	$(GO) test ./protocol/... ./security/... -run '^$$' -bench . -benchmem -count=1 || true
	$(GO) run ./cmd/batur bench

demo:
	$(GO) run ./cmd/batur demo

doctor:
	$(GO) run ./cmd/batur doctor

fuzz:
	$(GO) test -run '^$$' -fuzz=FuzzDecodeDefault -fuzztime=$(FUZZTIME) ./protocol/binary/
	$(GO) test -run '^$$' -fuzz=FuzzEncodeNode   -fuzztime=$(FUZZTIME) ./protocol/binary/
	$(GO) test -run '^$$' -fuzz=FuzzParse        -fuzztime=$(FUZZTIME) ./protocol/pb/

cross:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/batur-linux-amd64 ./cmd/batur
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/batur-linux-arm64 ./cmd/batur
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 $(GO) build -trimpath -ldflags '$(LDFLAGS)' -o $(BIN)/batur-darwin-arm64 ./cmd/batur

clean:
	rm -rf $(BIN)
