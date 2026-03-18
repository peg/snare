//go:build !linux && !darwin

package cli

import "fmt"

// termios is a stub for unsupported platforms.
type termios struct{}

func makeRaw(_ int) (*termios, error) {
	return nil, fmt.Errorf("--select requires a Linux or macOS terminal")
}

func restoreTerminal(_ int, _ *termios) {}
