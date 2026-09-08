# Bundled Capstone build for DeStruct
# Builds a static libcapstone.a from the vendored Capstone 6.0.0-Alpha10 source.
# Only ARM and ARM64 architectures are compiled to minimize binary size.

CAPSTONE_DIR := ../../capstone-6.0.0-Alpha10
BUILD_DIR := build

CC ?= gcc
AR ?= ar
CFLAGS := -O3 -std=gnu99 -fPIC -Wall -Wwrite-strings -Wmissing-prototypes
CFLAGS += -I$(CAPSTONE_DIR)/include -DCAPSTONE_HAS_ARM -DCAPSTONE_HAS_AARCH64
CFLAGS += -DCAPSTONE_USE_SYS_DYN_MEM

# Core source files (always needed)
CORE_SRCS := \
	$(CAPSTONE_DIR)/cs.c \
	$(CAPSTONE_DIR)/utils.c \
	$(CAPSTONE_DIR)/SStream.c \
	$(CAPSTONE_DIR)/MCInstrDesc.c \
	$(CAPSTONE_DIR)/MCRegisterInfo.c \
	$(CAPSTONE_DIR)/MCInst.c \
	$(CAPSTONE_DIR)/MCInstPrinter.c \
	$(CAPSTONE_DIR)/Mapping.c

# ARM architecture sources
ARM_SRCS := $(wildcard $(CAPSTONE_DIR)/arch/ARM/*.c)

# AArch64 architecture sources
AARCH64_SRCS := $(wildcard $(CAPSTONE_DIR)/arch/AArch64/*.c)

ALL_SRCS := $(CORE_SRCS) $(ARM_SRCS) $(AARCH64_SRCS)
ALL_OBJS := $(patsubst $(CAPSTONE_DIR)/%.c,$(BUILD_DIR)/%.o,$(ALL_SRCS))

LIBRARY := $(BUILD_DIR)/libcapstone.a

.PHONY: all clean

all: $(LIBRARY)

$(LIBRARY): $(ALL_OBJS)
	$(AR) rcs $@ $^

$(BUILD_DIR)/%.o: $(CAPSTONE_DIR)/%.c
	@mkdir -p $(dir $@)
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
