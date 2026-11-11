.PHONY: build test acceptance compat check
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -trimpath -o bin/scribe ./cmd/scribe
test:
	go test -race ./...
acceptance:
	cd examples/external && go test -race ./... && go vet ./...
compat:
	go run ./cmd/scribe-compat --manifest compat/manifest.json --out compat/report.json
check: test acceptance
	go vet ./...
