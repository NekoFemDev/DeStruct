# Bundled Unicorn Engine build for DeStruct's optional emulation.
# Builds a static libunicorn.a with only the AArch64 backend.
#
# UNICORN_DIR defaults to the stable unicorn-src symlink at the repo root
# (maintained by fetch-unicorn.sh / top-level make).
#
# Unicorn is GPLv2. This library is only linked by builds using the
# `unicorn` Go build tag.

UNICORN_DIR ?= ../../unicorn-src
BUILD_DIR := build
CMAKE ?= cmake

ifeq ($(wildcard $(UNICORN_DIR)/CMakeLists.txt),)
  UNICORN_DIR := $(lastword $(sort $(wildcard ../../unicorn-*)))
endif

LIBRARY := $(BUILD_DIR)/libunicorn.a

.PHONY: all clean

all: $(LIBRARY)

$(LIBRARY): $(UNICORN_DIR)/CMakeLists.txt
	$(CMAKE) -S $(UNICORN_DIR) -B $(BUILD_DIR) \
		-DCMAKE_BUILD_TYPE=Release \
		-DUNICORN_ARCH=aarch64 \
		-DUNICORN_BUILD_TESTS=OFF \
		-DUNICORN_INSTALL=OFF \
		-DUNICORN_LEGACY_STATIC_ARCHIVE=ON
	$(CMAKE) --build $(BUILD_DIR) -j"$$(nproc)"

clean:
	rm -rf $(BUILD_DIR)
