GO ?= go
VERSION ?= dev
export VERSION

.PHONY: build test race lint security release verify-release clean

build:
	CGO_ENABLED=0 $(GO) build -trimpath -buildvcs=false -ldflags "-X ssmh/internal/version.Version=$$VERSION" -o bin/ssmh ./cmd/ssmh

test:
	$(GO) test ./...

race:
	$(GO) test -race ./...

lint:
	$(GO) vet ./...

security:
	$(GO) mod verify
	$(GO) vet ./...
	$(GO) test -race ./...
	govulncheck ./...

release:
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 $(GO) build -trimpath -buildvcs=false -ldflags "-s -w -X ssmh/internal/version.Version=$$VERSION" -o dist/ssmh-linux-amd64 ./cmd/ssmh
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 $(GO) build -trimpath -buildvcs=false -ldflags "-s -w -X ssmh/internal/version.Version=$$VERSION" -o dist/ssmh-linux-arm64 ./cmd/ssmh

# Requires cached dependencies; builds isolated copies, not workspace artifacts.
verify-release:
	SSMH_TEST_BUILD=1 $(GO) test ./tests/build -run '^TestReleaseReproducibility$$' -count=1 -timeout=6m -v

# Only exact generated binary targets are removed, never entire directories.
clean:
	$(RM) bin/ssmh dist/ssmh-linux-amd64 dist/ssmh-linux-arm64
