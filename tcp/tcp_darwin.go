//go:build darwin

package tcp

import (
	"errors"
	"net"

	"golang.org/x/sys/unix"
)

// GetWindow returns the TCP send/receive buffer sizes on macOS
func GetWindow(nconn net.Conn) (sndWnd, rcvWnd int, err error) {
	conn, ok := nconn.(*net.TCPConn)
	if !ok {
		return 0, 0, errors.New("not a TCP connection")
	}
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
