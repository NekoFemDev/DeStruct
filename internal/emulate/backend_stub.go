//go:build !unicorn

package emulate

// Built without the optional Unicorn backend. newBackend stays nil and the
// public API returns ErrUnavailable with build instructions.
