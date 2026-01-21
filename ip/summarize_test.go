package ip

import (
	"encoding/binary"
	"net"
	"strings"
	"testing"
)

func TestTcpFlagsStr(t *testing.T) {
	tests := []struct {
		name  string
		flags byte
		want  string
	}{
		{"no flags", 0x00, ""},
		{"SYN only", 0x02, "SYN"},
		{"ACK only", 0x10, "ACK"},
		{"FIN only", 0x01, "FIN"},
		{"RST only", 0x04, "RST"},
		{"SYN ACK", 0x12, "SYN ACK"},
		{"FIN ACK", 0x11, "ACK FIN"},
		{"SYN FIN ACK RST", 0x17, "SYN ACK FIN RST"},
		{"all flags", 0xFF, "SYN ACK FIN RST"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tcpFlagsStr(tt.flags)
			if got != tt.want {
				t.Errorf("tcpFlagsStr(0x%02x) = %q, want %q", tt.flags, got, tt.want)
			}
		})
	}
}

func TestSummarizePacket_IPv4_TCP(t *testing.T) {
	pkt := createTCPPacket(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("10.0.0.1"),
		443, 52341,
		0x02, // SYN
	)

	result := SummarizePacket(pkt)

	if !strings.Contains(result, "IPv4") {
		t.Errorf("expected IPv4 in result, got %s", result)
	}
	if !strings.Contains(result, "TCP") {
		t.Errorf("expected TCP in result, got %s", result)
	}
	if !strings.Contains(result, "192.168.1.1") {
		t.Errorf("expected source IP in result, got %s", result)
	}
	if !strings.Contains(result, "10.0.0.1") {
		t.Errorf("expected dest IP in result, got %s", result)
	}
}

func TestSummarizePacket_IPv4_UDP(t *testing.T) {
	pkt := createUDPPacket(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("8.8.8.8"),
		12345, 53,
		[]byte("test payload"),
	)

	result := SummarizePacket(pkt)

	if !strings.Contains(result, "IPv4") {
		t.Errorf("expected IPv4 in result, got %s", result)
	}
	if !strings.Contains(result, "UDP") {
		t.Errorf("expected UDP in result, got %s", result)
	}
}

func TestSummarizePacket_Invalid(t *testing.T) {
	tests := []struct {
		name string
		pkt  []byte
	}{
		{"empty", []byte{}},
		{"too short", []byte{0x45}},
		{"invalid version", []byte{0x35, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SummarizePacket(tt.pkt)
			if result == "" {
				t.Error("expected non-empty result for invalid packet")
			}
		})
	}
}

func BenchmarkTcpFlagsStr(b *testing.B) {
	flags := []byte{0x00, 0x02, 0x10, 0x12, 0x11, 0x17}
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		tcpFlagsStr(flags[i%len(flags)])
	}
}

func BenchmarkSummarizePacket_TCP(b *testing.B) {
	pkt := createTCPPacket(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("10.0.0.1"),
		443, 52341,
		0x12, // SYN+ACK
	)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SummarizePacket(pkt)
	}
}

func BenchmarkSummarizePacket_UDP(b *testing.B) {
	pkt := createUDPPacket(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("8.8.8.8"),
		12345, 53,
		[]byte("test"),
	)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		SummarizePacket(pkt)
	}
}

// Helper: create minimal IPv4 TCP packet
func createTCPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, flags byte) []byte {
	tcpHeaderLen := 20
	ipHeaderLen := 20
	totalLen := ipHeaderLen + tcpHeaderLen

	pkt := make([]byte, totalLen)

	// IPv4 header
	pkt[0] = 0x45 // Version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[9] = 6 // TCP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())

	// TCP header
	tcp := pkt[ipHeaderLen:]
	binary.BigEndian.PutUint16(tcp[0:2], srcPort)
	binary.BigEndian.PutUint16(tcp[2:4], dstPort)
	binary.BigEndian.PutUint32(tcp[4:8], 1000)  // seq
	binary.BigEndian.PutUint32(tcp[8:12], 2000) // ack
	tcp[12] = 0x50                              // data offset = 5 (20 bytes)
	tcp[13] = flags

	return pkt
}

// Helper: create minimal IPv4 UDP packet
func createUDPPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, payload []byte) []byte {
	udpHeaderLen := 8
	ipHeaderLen := 20
	totalLen := ipHeaderLen + udpHeaderLen + len(payload)

	pkt := make([]byte, totalLen)

	// IPv4 header
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[9] = 17 // UDP
	copy(pkt[12:16], srcIP.To4())
	copy(pkt[16:20], dstIP.To4())

	// UDP header
	udp := pkt[ipHeaderLen:]
	binary.BigEndian.PutUint16(udp[0:2], srcPort)
	binary.BigEndian.PutUint16(udp[2:4], dstPort)
	binary.BigEndian.PutUint16(udp[4:6], uint16(udpHeaderLen+len(payload)))
	copy(udp[8:], payload)

	return pkt
}
