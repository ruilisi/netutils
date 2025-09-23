//go:build windows

package tcp

import (
	"errors"
	"net"
	"unsafe"

	"golang.org/x/sys/windows"
)

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
	fd := windows.Handle(file.Fd())

	var opt int32
	var size int32 = 4

	err = windows.Getsockopt(fd, windows.SOL_SOCKET, windows.SO_RCVBUF, (*byte)(unsafe.Pointer(&opt)), &size)
	if err != nil {
		return 0, 0, err
	}
	rcvWnd = int(opt)

	err = windows.Getsockopt(fd, windows.SOL_SOCKET, windows.SO_SNDBUF, (*byte)(unsafe.Pointer(&opt)), &size)
	if err != nil {
		return 0, 0, err
	}
	sndWnd = int(opt)

	return sndWnd, rcvWnd, nil
}
