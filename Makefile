.PHONY: build build-unicorn clean test test-race vet lint fmt run capstone ensure-capstone download download-unicorn capstone-latest update-capstone capstone-version capstone-clean unicorn ensure-unicorn unicorn-clean install-termux uninstall-termux

BINARY=destruct
MODULE=github.com/destruct/destruct
CAPSTONE_DIR=third_party/capstone
UNICORN_DIR=third_party/unicorn
# Pinned default. Override on the command line:
#   make build CAPSTONE_VERSION=6.0.0-Alpha10
# or roll forward to whatever is newest upstream:
#   make update-capstone          # latest tag, rebuilds lib
CAPSTONE_VERSION ?= 6.0.0-Alpha11
CAPSTONE_SRC=capstone-$(CAPSTONE_VERSION)
CAPSTONE_SYMLINK=capstone-src
CAPSTONE_URL=https://github.com/capstone-engine/capstone/archive/refs/tags/$(CAPSTONE_VERSION).tar.gz
# NOTE: the archive URL needs the .tar.gz (or .zip) suffix - the bare
# .../archive/refs/tags/$version without a suffix returns 404.
FETCH_SCRIPT=$(CAPSTONE_DIR)/fetch-capstone.sh

# Optional Unicorn emulation (GPLv2). Only linked by build-unicorn.
UNICORN_VERSION ?= 2.1.4
UNICORN_SRC=unicorn-$(UNICORN_VERSION)
UNICORN_SYMLINK=unicorn-src
UNICORN_FETCH=$(UNICORN_DIR)/fetch-unicorn.sh

build: capstone
	go build -o $(BINARY) ./cmd/destruct

# GPLv2 binary: includes Unicorn-based AArch64 emulation.
build-unicorn: unicorn
	go build -tags unicorn -o $(BINARY) ./cmd/destruct

capstone: ensure-capstone
	$(MAKE) -C $(CAPSTONE_DIR) CAPSTONE_DIR=../../$(CAPSTONE_SYMLINK)

# Ensure capstone-src points at the pinned version, fetching it if needed.
# Idempotent: a correct symlink is a no-op.
ensure-capstone:
	@if [ "$$(readlink $(CAPSTONE_SYMLINK) 2>/dev/null)" != "$(CAPSTONE_SRC)" ]; then \
		echo "Downloading Capstone $(CAPSTONE_VERSION)..."; \
		sh $(FETCH_SCRIPT) $(CAPSTONE_VERSION); \
	fi

$(CAPSTONE_SYMLINK): ensure-capstone

download: $(CAPSTONE_SYMLINK)

# Print the newest upstream tag (git ls-remote, API fallback).
capstone-latest:
	sh $(FETCH_SCRIPT) latest

# Fetch the newest upstream tag (or VERSION=<tag>), repoint
# capstone-src, and rebuild libcapstone.a from scratch.
# After this, bump CAPSTONE_VERSION above to the printed tag so the
# pin stays reproducible.
update-capstone:
	@if [ -n "$(VERSION)" ]; then \
		sh $(FETCH_SCRIPT) $(VERSION); \
	else \
		sh $(FETCH_SCRIPT) latest; \
	fi
	$(MAKE) -C $(CAPSTONE_DIR) clean
	$(MAKE) -C $(CAPSTONE_DIR) CAPSTONE_DIR=../../$(CAPSTONE_SYMLINK)
	@echo "Pinned CAPSTONE_VERSION is still $(CAPSTONE_VERSION) - update it to:"
	@readlink $(CAPSTONE_SYMLINK) | sed 's/^capstone-//'

capstone-version:
	@echo $(CAPSTONE_VERSION)

capstone-clean:
	rm -rf capstone-*/ $(CAPSTONE_SYMLINK)
	$(MAKE) -C $(CAPSTONE_DIR) clean

# Optional Unicorn emulation (GPLv2).
unicorn: ensure-unicorn
	$(MAKE) -C $(UNICORN_DIR) UNICORN_DIR=../../$(UNICORN_SYMLINK)

ensure-unicorn:
	@if [ "$$(readlink $(UNICORN_SYMLINK) 2>/dev/null)" != "$(UNICORN_SRC)" ]; then \
		echo "Downloading Unicorn $(UNICORN_VERSION)..."; \
		sh $(UNICORN_FETCH) $(UNICORN_VERSION); \
	fi

$(UNICORN_SYMLINK): ensure-unicorn

download-unicorn: $(UNICORN_SYMLINK)

unicorn-clean:
	rm -rf unicorn-*/ $(UNICORN_SYMLINK)
	$(MAKE) -C $(UNICORN_DIR) clean

clean:
	rm -f $(BINARY)
	rm -rf output/
	$(MAKE) -C $(CAPSTONE_DIR) clean
	$(MAKE) -C $(UNICORN_DIR) clean

# Termux/Android one-shot installer: installs deps, fetches Capstone,
# builds, and installs $(BINARY) into $PREFIX/bin. Accepts the same flags
# as the script itself, e.g.:
#   make install-termux INSTALL_ARGS="--update --clean"
install-termux:
	bash install-termux.sh $(INSTALL_ARGS)

uninstall-termux:
	bash install-termux.sh --uninstall

test:
	go test ./...

test-race:
	go test -race ./...

vet:
	go vet ./...

fmt:
	gofmt -w $$(find . -name '*.go' -not -path './capstone-*' -not -path './unicorn-*' -not -path './third_party/*')

lint:
	golangci-lint run

run:
	go run ./cmd/destruct

help:
	@echo "DeStruct - Multi-format decompiler & reverse-engineering toolkit"
	@echo ""
	@echo "Usage:"
	@echo "  make build    Build the binary (includes Capstone)"
	@echo "  make build-unicorn  Build with optional Unicorn emulation (GPLv2)"
	@echo "  make install-termux  Install to $$PREFIX/bin on Termux (flags: INSTALL_ARGS=\"--update\")"
	@echo "  make uninstall-termux Remove the Termux install"
	@echo "  make download Download pinned Capstone source (Capstone $(CAPSTONE_VERSION))"
	@echo "  make update-capstone Fetch latest upstream Capstone and rebuild"
	@echo "  make capstone-latest Print latest upstream Capstone tag"
	@echo "  make capstone-clean Remove all fetched Capstone sources"
	@echo "  make unicorn  Build pinned Unicorn $(UNICORN_VERSION) (AArch64 only, GPLv2)"
	@echo "  make download-unicorn Download pinned Unicorn source"
	@echo "  make unicorn-clean Remove fetched Unicorn sources"
	@echo "  make clean    Remove build artifacts"
	@echo "  make test     Run tests"
	@echo "  make test-race Run tests with the race detector"
	@echo "  make vet      Run go vet"
	@echo "  make fmt      Format all Go sources"
	@echo "  make lint     Run golangci-lint"
	@echo "  make run      Run without building"
	@echo "  make help     Show this help"
