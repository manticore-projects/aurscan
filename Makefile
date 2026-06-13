BIN     := aurscan
PREFIX  ?= /usr/local
LDFLAGS := -s -w
GOFLAGS := -trimpath -ldflags="$(LDFLAGS)"

build:
	CGO_ENABLED=0 go build $(GOFLAGS) -o $(BIN) ./cmd/aurscan

test:
	go vet ./...
	go test ./...

# Compress the built binary in place with UPX (best/lzma) and verify it.
# Needs `upx` on PATH (pacman -S upx). No-op-safe to rerun: rebuilds first.
compress: build
	@command -v upx >/dev/null || { echo "upx not found (pacman -S upx)"; exit 1; }
	upx --best --lzma $(BIN)
	upx -t $(BIN)

# Cross-build release artifacts: static linux/amd64 (UPX-packed) and
# linux/arm64 (uncompressed). Mirrors the GitHub release job.
release:
	@command -v upx >/dev/null || { echo "upx not found (pacman -S upx)"; exit 1; }
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build $(GOFLAGS) -o aurscan-linux-amd64 ./cmd/aurscan
	upx --best --lzma aurscan-linux-amd64 && upx -t aurscan-linux-amd64
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build $(GOFLAGS) -o aurscan-linux-arm64 ./cmd/aurscan

install: build
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/bin/$(BIN)
	ln -sf $(BIN) $(DESTDIR)$(PREFIX)/bin/syay
	ln -sf $(BIN) $(DESTDIR)$(PREFIX)/bin/aurscan-edit

clean:
	rm -f $(BIN) aurscan-linux-amd64 aurscan-linux-arm64

.PHONY: build test compress release install clean
