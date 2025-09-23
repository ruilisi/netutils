package tcp

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestGetWindow dials a TCP connection and checks the window sizes
func TestGetWindow(t *testing.T) {
	conn, err := net.Dial("tcp", "lingti.com:80")
	if err != nil {
		t.Fatalf("Failed to connect: %v", err)
	}
	tcpConn := conn.(*net.TCPConn)
	defer tcpConn.Close()

	snd, rcv, err := GetWindow(tcpConn)
	if err != nil {
		t.Fatalf("GetWindow returned error: %v", err)
	}

	if snd <= 0 {
		t.Errorf("Send window should be positive, got %d", snd)
	}
	if rcv <= 0 {
		t.Errorf("Receive window should be positive, got %d", rcv)
	}

	t.Logf("TCP Send Window: %d bytes", snd)
	t.Logf("TCP Receive Window: %d bytes", rcv)

	SetWindow(tcpConn, 1024, 102400)
	snd, rcv, err = GetWindow(tcpConn)
	assert.Equal(t, snd, 1024, "send window should be set correctly")
	snd, rcv, err = GetWindow(tcpConn)
	assert.Equal(t, rcv, 102400, "recv window should be set correctly")
}
