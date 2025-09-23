package tcp

import (
	"errors"
	"fmt"
	"net"
)

func SetWindow(conn net.Conn, sendSize int, recvSize int) error {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return errors.New("not a TCP connection")
	}
	if err := tcpConn.SetWriteBuffer(sendSize); err != nil {
		return fmt.Errorf("failed to set send size: %v", err)
	}
	if err := tcpConn.SetReadBuffer(recvSize); err != nil {
		return fmt.Errorf("failed to set recv size: %v", err)
	}
	return nil
}
