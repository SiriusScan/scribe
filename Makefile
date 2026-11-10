.PHONY: build test check
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/scribe ./cmd/scribe
test:
	go test -race ./...
check: test
	go vet ./...
