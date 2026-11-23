package emulate

import (
	"errors"
	"testing"
)

func TestUnavailableWithoutTag(t *testing.T) {
	if Available() {
		t.Skip("built with the unicorn backend")
	}
	if _, err := NewMachine(ArchARM64, DefaultConfig()); !errors.Is(err, ErrUnavailable) {
		t.Fatalf("NewMachine error = %v, want ErrUnavailable", err)
	}
}
