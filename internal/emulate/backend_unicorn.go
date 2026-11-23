//go:build unicorn

package emulate

/*
#cgo CFLAGS: -I${SRCDIR}/../../unicorn-src/include
#cgo LDFLAGS: ${SRCDIR}/../../third_party/unicorn/build/libunicorn.a -lpthread -lm
#include <unicorn/unicorn.h>
*/
import "C"

import (
	"fmt"
	"strconv"
	"strings"
	"time"
	"unsafe"
)

func init() {
	newBackend = newUnicornBackend
}

type unicornBackend struct {
	uc     *C.uc_engine
	closed bool
}

func newUnicornBackend(arch Arch) (Backend, error) {
	if arch != ArchARM64 {
		return nil, fmt.Errorf("unicorn backend: unsupported architecture %d (only ARM64)", arch)
	}
	var uc *C.uc_engine
	if err := C.uc_open(C.UC_ARCH_ARM64, C.UC_MODE_ARM, &uc); err != C.UC_ERR_OK {
		return nil, unicornError(err)
	}
	return &unicornBackend{uc: uc}, nil
}

func unicornError(err C.uc_err) error {
	return fmt.Errorf("unicorn: %s", C.GoString(C.uc_strerror(err)))
}

func (b *unicornBackend) Map(addr, size uint64, prot int) error {
	if err := C.uc_mem_map(b.uc, C.uint64_t(addr), C.uint64_t(size), C.uint32_t(prot)); err != C.UC_ERR_OK {
		return unicornError(err)
	}
	return nil
}

func (b *unicornBackend) Write(addr uint64, data []byte) error {
	if len(data) == 0 {
		return nil
	}
	if err := C.uc_mem_write(b.uc, C.uint64_t(addr), unsafe.Pointer(&data[0]), C.size_t(len(data))); err != C.UC_ERR_OK {
		return unicornError(err)
	}
	return nil
}

func (b *unicornBackend) Read(addr, size uint64) ([]byte, error) {
	buf := make([]byte, size)
	if size == 0 {
		return buf, nil
	}
	if err := C.uc_mem_read(b.uc, C.uint64_t(addr), unsafe.Pointer(&buf[0]), C.size_t(size)); err != C.UC_ERR_OK {
		return nil, unicornError(err)
	}
	return buf, nil
}

func (b *unicornBackend) Reg(name string) (int, error) {
	lower := strings.ToLower(name)
	switch lower {
	case "sp":
		return int(C.UC_ARM64_REG_SP), nil
	case "pc":
		return int(C.UC_ARM64_REG_PC), nil
	case "nzcv":
		return int(C.UC_ARM64_REG_NZCV), nil
	case "tpidr_el0":
		return int(C.UC_ARM64_REG_TPIDR_EL0), nil
	case "lr":
		return int(C.UC_ARM64_REG_X30), nil
	case "fp":
		return int(C.UC_ARM64_REG_X29), nil
	}
	if strings.HasPrefix(lower, "x") {
		n, err := strconv.Atoi(lower[1:])
		if err == nil && n >= 0 && n <= 30 {
			switch n {
			case 29:
				return int(C.UC_ARM64_REG_X29), nil
			case 30:
				return int(C.UC_ARM64_REG_X30), nil
			default:
				return int(C.UC_ARM64_REG_X0) + n, nil
			}
		}
	}
	return 0, fmt.Errorf("unknown ARM64 register %q", name)
}

func (b *unicornBackend) RegWrite(reg int, value uint64) error {
	v := C.uint64_t(value)
	if err := C.uc_reg_write(b.uc, C.int(reg), unsafe.Pointer(&v)); err != C.UC_ERR_OK {
		return unicornError(err)
	}
	return nil
}

func (b *unicornBackend) RegRead(reg int) (uint64, error) {
	var v C.uint64_t
	if err := C.uc_reg_read(b.uc, C.int(reg), unsafe.Pointer(&v)); err != C.UC_ERR_OK {
		return 0, unicornError(err)
	}
	return uint64(v), nil
}

func (b *unicornBackend) Start(begin, until uint64, timeout time.Duration, count uint64) error {
	micros := uint64(0)
	if timeout > 0 {
		micros = uint64(timeout / time.Microsecond)
	}
	if err := C.uc_emu_start(b.uc, C.uint64_t(begin), C.uint64_t(until), C.uint64_t(micros), C.size_t(count)); err != C.UC_ERR_OK {
		return unicornError(err)
	}
	return nil
}

func (b *unicornBackend) Close() error {
	if b.closed {
		return nil
	}
	b.closed = true
	if b.uc == nil {
		return nil
	}
	if err := C.uc_close(b.uc); err != C.UC_ERR_OK {
		return unicornError(err)
	}
	b.uc = nil
	return nil
}
