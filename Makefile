.PHONY: build clean test capstone download

BINARY=destruct
MODULE=github.com/destruct/destruct
CAPSTONE_DIR=third_party/capstone
CAPSTONE_VERSION=6.0.0-Alpha10
CAPSTONE_URL=https://github.com/capstone-engine/capstone/archive/refs/tags/$(CAPSTONE_VERSION).zip

build: capstone
	go build -o $(BINARY) ./cmd/destruct

capstone: $(CAPSTONE_DIR)/build/libcapstone.a

$(CAPSTONE_DIR)/build/libcapstone.a: capstone-$(CAPSTONE_VERSION)/
	$(MAKE) -C $(CAPSTONE_DIR)

capstone-$(CAPSTONE_VERSION)/:
	@echo "Downloading Capstone $(CAPSTONE_VERSION)..."
	curl -L -o /tmp/capstone.zip $(CAPSTONE_URL)
	unzip -q /tmp/capstone.zip
	mv capstone-$(CAPSTONE_VERSION) capstone-$(CAPSTONE_VERSION).tmp
	mv capstone-$(CAPSTONE_VERSION).tmp capstone-$(CAPSTONE_VERSION)
	rm /tmp/capstone.zip

download:
	@echo "Downloading Capstone $(CAPSTONE_VERSION)..."
	curl -L -o /tmp/capstone.zip $(CAPSTONE_URL)
	unzip -q /tmp/capstone.zip
	mv capstone-$(CAPSTONE_VERSION) capstone-$(CAPSTONE_VERSION).tmp
	mv capstone-$(CAPSTONE_VERSION).tmp capstone-$(CAPSTONE_VERSION)
	rm /tmp/capstone.zip

clean:
	rm -f $(BINARY)
	rm -rf output/
	$(MAKE) -C $(CAPSTONE_DIR) clean

test:
	go test ./...

vet:
	go vet ./...

lint:
	golangci-lint run

run:
	go run ./cmd/destruct

help:
	@echo "DeStruct - Decompiler to C#"
	@echo ""
	@echo "Usage:"
	@echo "  make build    Build the binary (includes Capstone)"
	@echo "  make download Download Capstone source"
	@echo "  make clean    Remove build artifacts"
	@echo "  make test     Run tests"
	@echo "  make vet      Run go vet"
	@echo "  make lint     Run golangci-lint"
	@echo "  make run      Run without building"
	@echo "  make help     Show this help"
