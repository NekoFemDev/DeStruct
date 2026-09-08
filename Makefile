.PHONY: build clean test capstone

BINARY=destruct
MODULE=github.com/destruct/destruct
CAPSTONE_DIR=third_party/capstone

build: capstone
	go build -o $(BINARY) ./cmd/destruct

capstone:
	$(MAKE) -C $(CAPSTONE_DIR)

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
	@echo "  make clean    Remove build artifacts"
	@echo "  make test     Run tests"
	@echo "  make vet      Run go vet"
	@echo "  make lint     Run golangci-lint"
	@echo "  make run      Run without building"
	@echo "  make help     Show this help"
