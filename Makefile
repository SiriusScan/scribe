.PHONY: build test acceptance check
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/scribe ./cmd/scribe
test:
	go test -race ./...
acceptance:
	cd examples/external && go test -race ./... && go vet ./...
check: test acceptance
	go vet ./...
