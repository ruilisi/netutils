//go:build linux

package tcp

import (
	"fmt"
	"net"
	"syscall"
)

func GetWindow(conn net.Conn) (sndBuf, rcvBuf int, err error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return 0, 0, fmt.Errorf("not a TCP connection")
	}

	file, err := tcpConn.File()
	if err != nil {
		return 0, 0, err
	}
	defer file.Close()

	fd := int(file.Fd())

	// Get send buffer size
	sndBuf, err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_SNDBUF)
	if err != nil {
		return 0, 0, err
	}

	// Get receive buffer size
	rcvBuf, err = syscall.GetsockoptInt(fd, syscall.SOL_SOCKET, syscall.SO_RCVBUF)
	if err != nil {
		return 0, 0, err
	}

	return sndBuf, rcvBuf, nil
}
