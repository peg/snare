package cli

import (
	"syscall"
	"unsafe"
)

// termios holds terminal attributes for raw mode (macOS/BSD layout).
type termios struct {
	Iflag  uint64
	Oflag  uint64
	Cflag  uint64
	Lflag  uint64
	Cc     [20]uint8
	Ispeed uint64
	Ospeed uint64
}

const (
	darwinTIOCGETA = 0x402c7413
	darwinTIOCSETA = 0x802c7414
)

func makeRaw(fd int) (*termios, error) {
	var old termios
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), darwinTIOCGETA, uintptr(unsafe.Pointer(&old))); errno != 0 {
		return nil, errno
	}
	raw := old
	raw.Lflag &^= syscall.ECHO | syscall.ICANON | syscall.ISIG | syscall.IEXTEN
	raw.Iflag &^= syscall.IXON | syscall.ICRNL | syscall.BRKINT | syscall.INPCK | syscall.ISTRIP
	raw.Cflag |= syscall.CS8
	raw.Oflag &^= syscall.OPOST
	raw.Cc[syscall.VMIN] = 1
	raw.Cc[syscall.VTIME] = 0
	if _, _, errno := syscall.Syscall(syscall.SYS_IOCTL,
		uintptr(fd), darwinTIOCSETA, uintptr(unsafe.Pointer(&raw))); errno != 0 {
		return nil, errno
	}
	return &old, nil
}

func restoreTerminal(fd int, old *termios) {
	if old == nil {
		return
	}
	syscall.Syscall(syscall.SYS_IOCTL, //nolint:errcheck
		uintptr(fd), darwinTIOCSETA, uintptr(unsafe.Pointer(old)))
}
