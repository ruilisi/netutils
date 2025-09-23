//go:build darwin

package tcp

import (
	"net"

	"golang.org/x/sys/unix"
)

// GetWindow returns the TCP send/receive buffer sizes on macOS
func GetWindow(conn *net.TCPConn) (sndWnd, rcvWnd int, err error) {
	file, err := conn.File()
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()
	fd := int(file.Fd())

	rcv, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_RCVBUF)
	if err != nil {
		return 0, 0, err
	}

	snd, err := unix.GetsockoptInt(fd, unix.SOL_SOCKET, unix.SO_SNDBUF)
	if err != nil {
		return 0, 0, err
	}

	return snd, rcv, nil
}
