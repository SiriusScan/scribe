VERSION ?= $(shell git describe --tags --always)
COMMIT := $(shell git rev-parse HEAD)
PREFIX ?= /usr/local
LDFLAGS = -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X github.com/SiriusScan/scribe.BuildVersion=$(VERSION) -X github.com/SiriusScan/scribe.BuildCommit=$(COMMIT)

.PHONY: build test acceptance compat check
build:
	mkdir -p bin
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS)" -trimpath -o bin/scribe ./cmd/scribe
test:
	go test -race ./...
acceptance:
	cd examples/external && go test -race ./... && go vet ./...
compat:
	go run ./cmd/scribe-compat --manifest compat/manifest.json --out compat/report.json
check: test acceptance cross-compile
	go vet ./...
	CGO_ENABLED=0 go build -o /tmp/scribe-check ./cmd/scribe

.PHONY: install
install: build
	install -d $(DESTDIR)$(PREFIX)/bin
	install -m 0755 bin/scribe $(DESTDIR)$(PREFIX)/bin/scribe
	@if [ -z "$(DESTDIR)" ] && systemctl is-active --quiet scribe.service; then systemctl restart scribe.service; fi

.PHONY: install-service restart-service smoke-http
# apps01 system deployment; run with sudo and the Go toolchain on PATH.
install-service: install
	install -m 0644 deploy/scribe.service /etc/systemd/system/scribe.service
	systemctl daemon-reload
	systemctl enable scribe.service
	systemctl restart scribe.service
restart-service:
	systemctl restart scribe.service
smoke-http:
	python3 scripts/smoke-http.py

.PHONY: cross-compile
cross-compile:
	@set -eu; tmp=$$(mktemp -d); trap 'rm -rf "$$tmp"' EXIT; \
	for platform in windows darwin; do \
		CGO_ENABLED=0 GOOS=$$platform GOARCH=amd64 go build -o "$$tmp/scribe-$$platform" ./cmd/scribe; \
	done


.PHONY: acceptance-local
# Controlled local sockets and SDK fixtures; not a live consumer workflow gate.
acceptance-local: acceptance
	go test -race -count=1 -v . -run 'Test(PingppSelectionParallelHTTP|HTTPAndTLSProbeCache|DirectSDKProbeOption|SSHListenerAcceptance)$$'
	go test -race -count=1 ./cmd/scribe -run 'TestPingppSelection$$'

	go test -count=1 -v ./adapter/pingpp -run TestRealEmitter
