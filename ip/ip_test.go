package ip

import (
	"encoding/binary"
	"fmt"
	"net"
	"testing"
)

func TestAddFullMask(t *testing.T) {
	tests := []struct {
		ip      string
		maskLen int
	}{
		{"192.168.1.0", 32},
		{"fe80::", 128},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			cidr := IP2IPNetFullMask(ip)

			if cidr.String() != fmt.Sprintf("%s/%d", tt.ip, tt.maskLen) {
				t.Errorf("IPWithFullMask failed for %s", tt.ip)
			}
		})
	}
}

func TestIsCIDRStrV6(t *testing.T) {
	tests := []struct {
		cidr    string
		want    bool
		wantErr bool
	}{
		// Valid IPv4 CIDRs
		{"192.168.1.0/24", false, false},
		{"10.0.0.0/8", false, false},
		{"0.0.0.0/0", false, false},

		// Valid IPv6 CIDRs
		{"2001:db8::/32", true, false},
		{"::1/128", true, false},
		{"fe80::/10", true, false},

		// Edge cases
		{"", false, true},               // empty string
		{"not.a.cidr", false, true},     // invalid format
		{"192.168.1.1", false, true},    // missing mask
		{"2001:db8::1", false, true},    // missing mask
		{"192.168.1.0/33", false, true}, // invalid IPv4 mask
		{"2001:db8::/129", false, true}, // invalid IPv6 mask
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			got, err := IsIPNetStrV6(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsIPv6CIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsIPv6CIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDefaultRoute(t *testing.T) {
	tests := []struct {
		ipnetStr string
		want     bool
	}{
		{"0.0.0.0/0", true},
		{"::/0", true},
		{"0.0.0.0/2", false},
		{"8.8.8.8/32", false},
		{"2001:db8::/32", false},
	}

	for _, tt := range tests {
		t.Run(tt.ipnetStr, func(t *testing.T) {
			_, ipnet, _ := net.ParseCIDR(tt.ipnetStr)
			if IsDefaultIPNet(ipnet) != tt.want {
				t.Errorf("failed to test default route for %s", tt.ipnetStr)
			}
		})
	}
}

func TestEqualIPNet(t *testing.T) {
	tests := []struct {
		a      string
		b      string
		expect bool
	}{
		{"192.168.1.0/24", "192.168.1.0/24", true},
		{"192.168.1.10/24", "192.168.1.0/24", true}, // masked IPs still same subnet
		{"192.168.1.0/24", "192.168.2.0/24", false},
		{"192.168.1.0/24", "192.168.1.0/25", false},
		{"240e:3a1:4c21:e310::/64", "240e:3a1:4c21:e310::/64", true},
		{"240e:3a1:4c21:e310::1/64", "240e:3a1:4c21:e310::/64", true},
		{"240e:3a1:4c21:e310::/64", "240e:3a1:4c21::/56", false},
		{"240e:3a1:4c21:e310::/32", "240e:3a1:4c21::/32", true},
	}

	for _, tt := range tests {
		_, netA, errA := net.ParseCIDR(tt.a)
		_, netB, errB := net.ParseCIDR(tt.b)
		if errA != nil || errB != nil {
			t.Fatalf("failed to parse CIDRs %q or %q", tt.a, tt.b)
		}

		if got := EqualIPNet(netA, netB); got != tt.expect {
			t.Errorf("EqualIPNet(%q, %q) = %v; want %v", tt.a, tt.b, got, tt.expect)
		}
	}
}

func TestGetOutboundInterface(t *testing.T) {
	iface, err := GetOutboundInterface()
	if err != nil {
		t.Fatalf("GetOutboundInterface failed: %v", err)
	}
	if iface == nil {
		t.Fatal("expected non-nil interface, got nil")
	}

	addrs, err := iface.Addrs()
	if err != nil {
		t.Fatalf("failed to get addresses for iface %s: %v", iface.Name, err)
	}
	if len(addrs) == 0 {
		t.Fatalf("interface %s has no addresses", iface.Name)
	}

	t.Logf("Outbound interface: %s (%v)", iface.Name, addrs)
}

func TestIsUDP(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		expected bool
	}{
		{
			name: "IPv4 UDP packet",
			packet: func() []byte {
				pkt := make([]byte, 28) // 20 IPv4 + 8 UDP
				pkt[0] = 0x45           // Version 4, header length 5
				pkt[9] = 17             // Protocol: UDP
				return pkt
			}(),
			expected: true,
		},
		{
			name: "IPv6 UDP packet",
			packet: func() []byte {
				pkt := make([]byte, 48) // 40 IPv6 + 8 UDP
				pkt[0] = 0x60           // Version 6
				pkt[6] = 17             // Next Header: UDP
				return pkt
			}(),
			expected: true,
		},
		{
			name: "IPv4 TCP packet",
			packet: func() []byte {
				pkt := make([]byte, 40) // 20 IPv4 + 20 TCP
				pkt[0] = 0x45           // Version 4, header length 5
				pkt[9] = 6              // Protocol: TCP
				return pkt
			}(),
			expected: false,
		},
		{
			name: "IPv6 TCP packet",
			packet: func() []byte {
				pkt := make([]byte, 60) // 40 IPv6 + 20 TCP
				pkt[0] = 0x60           // Version 6
				pkt[6] = 6              // Next Header: TCP
				return pkt
			}(),
			expected: false,
		},
		{
			name: "IPv4 ICMP packet",
			packet: func() []byte {
				pkt := make([]byte, 28) // 20 IPv4 + 8 ICMP
				pkt[0] = 0x45           // Version 4, header length 5
				pkt[9] = 1              // Protocol: ICMP
				return pkt
			}(),
			expected: false,
		},
		{
			name: "IPv6 ICMPv6 packet",
			packet: func() []byte {
				pkt := make([]byte, 44) // 40 IPv6 + 4 ICMPv6
				pkt[0] = 0x60           // Version 6
				pkt[6] = 58             // Next Header: ICMPv6
				return pkt
			}(),
			expected: false,
		},
		{
			name:     "empty packet",
			packet:   []byte{},
			expected: false,
		},
		{
			name:     "too short packet",
			packet:   []byte{0x45},
			expected: false,
		},
		{
			name: "invalid IP version",
			packet: func() []byte {
				pkt := make([]byte, 20)
				pkt[0] = 0x35 // Version 3 (invalid)
				return pkt
			}(),
			expected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := IsUDP(tt.packet)
			if result != tt.expected {
				t.Errorf("IsUDP() = %v, want %v", result, tt.expected)
			}
		})
	}
}

func TestSummarizePacketIPv6(t *testing.T) {
	tests := []struct {
		name     string
		packet   []byte
		expected string
	}{
		{
			name:     "too short packet",
			packet:   []byte{0x60}, // Just version
			expected: "invalid IPv6 packet (too short)",
		},
		{
			name: "IPv6 UDP packet",
			packet: func() []byte {
				// Create a minimal IPv6 UDP packet
				pkt := make([]byte, 48) // 40 IPv6 + 8 UDP

				// IPv6 header
				pkt[0] = 0x60                           // Version 6
				binary.BigEndian.PutUint16(pkt[4:6], 8) // Payload length = 8 (UDP header)
				pkt[6] = 17                             // Next Header = UDP
				pkt[7] = 64                             // Hop Limit

				// Source IP: 2001:db8::1
				copy(pkt[8:24], net.ParseIP("2001:db8::1"))
				// Dest IP: 2001:db8::2
				copy(pkt[24:40], net.ParseIP("2001:db8::2"))

				// UDP header
				binary.BigEndian.PutUint16(pkt[40:42], 1234) // Source port
				binary.BigEndian.PutUint16(pkt[42:44], 5678) // Dest port
				binary.BigEndian.PutUint16(pkt[44:46], 8)    // UDP length
				binary.BigEndian.PutUint16(pkt[46:48], 0)    // Checksum

				return pkt
			}(),
			expected: "IPv6 2001:db8::1:1234→2001:db8::2:5678 UDP | 0B",
		},
		{
			name: "IPv6 TCP packet",
			packet: func() []byte {
				// Create a minimal IPv6 TCP packet
				pkt := make([]byte, 60) // 40 IPv6 + 20 TCP

				// IPv6 header
				pkt[0] = 0x60                            // Version 6
				binary.BigEndian.PutUint16(pkt[4:6], 20) // Payload length = 20 (TCP header)
				pkt[6] = 6                               // Next Header = TCP
				pkt[7] = 64                              // Hop Limit

				// Source IP: fe80::1
				copy(pkt[8:24], net.ParseIP("fe80::1"))
				// Dest IP: fe80::2
				copy(pkt[24:40], net.ParseIP("fe80::2"))

				// TCP header
				binary.BigEndian.PutUint16(pkt[40:42], 8080) // Source port
				binary.BigEndian.PutUint16(pkt[42:44], 80)   // Dest port
				binary.BigEndian.PutUint32(pkt[44:48], 1000) // Seq number
				binary.BigEndian.PutUint32(pkt[48:52], 2000) // Ack number
				pkt[52] = 0x50                               // Data offset = 5 (20 bytes)
				pkt[53] = 0x02                               // Flags = SYN
				binary.BigEndian.PutUint16(pkt[54:56], 8192) // Window

				return pkt
			}(),
			expected: "IPv6 fe80::1:8080→fe80::2:80 TCP 👋 | Seq=1000 Ack=2000 | 0B",
		},
		{
			name: "IPv6 ICMPv6 packet",
			packet: func() []byte {
				// Create a minimal IPv6 ICMPv6 packet
				pkt := make([]byte, 44) // 40 IPv6 + 4 ICMPv6

				// IPv6 header
				pkt[0] = 0x60                           // Version 6
				binary.BigEndian.PutUint16(pkt[4:6], 4) // Payload length = 4 (ICMPv6 header)
				pkt[6] = 58                             // Next Header = ICMPv6
				pkt[7] = 64                             // Hop Limit

				// Source IP: ::1
				copy(pkt[8:24], net.ParseIP("::1"))
				// Dest IP: ::2
				copy(pkt[24:40], net.ParseIP("::2"))

				// ICMPv6 header
				pkt[40] = 128                             // Type = Echo Request
				pkt[41] = 0                               // Code
				binary.BigEndian.PutUint16(pkt[42:44], 0) // Checksum

				return pkt
			}(),
			expected: "IPv6 ::1→::2 ICMPv6 Echo Req | 0B",
		},
		{
			name: "IPv6 unknown protocol",
			packet: func() []byte {
				// Create IPv6 packet with unknown next header
				pkt := make([]byte, 40) // Just IPv6 header

				// IPv6 header
				pkt[0] = 0x60                           // Version 6
				binary.BigEndian.PutUint16(pkt[4:6], 0) // Payload length = 0
				pkt[6] = 99                             // Next Header = unknown
				pkt[7] = 64                             // Hop Limit

				// Source IP: 2001:db8::1
				copy(pkt[8:24], net.ParseIP("2001:db8::1"))
				// Dest IP: 2001:db8::2
				copy(pkt[24:40], net.ParseIP("2001:db8::2"))

				return pkt
			}(),
			expected: "IPv6 2001:db8::1→2001:db8::2 | Proto=99 | 0B",
		},
		{
			name: "IPv6 with extension header",
			packet: func() []byte {
				// Create IPv6 packet with Hop-by-Hop options header
				pkt := make([]byte, 56) // 40 IPv6 + 8 hop-by-hop + 8 UDP

				// IPv6 header
				pkt[0] = 0x60                            // Version 6
				binary.BigEndian.PutUint16(pkt[4:6], 16) // Payload length = 16 (8 hop-by-hop + 8 UDP)
				pkt[6] = 0                               // Next Header = Hop-by-Hop Options
				pkt[7] = 64                              // Hop Limit

				// Source IP: 2001:db8::1
				copy(pkt[8:24], net.ParseIP("2001:db8::1"))
				// Dest IP: 2001:db8::2
				copy(pkt[24:40], net.ParseIP("2001:db8::2"))

				// Hop-by-Hop Options header (8 bytes)
				pkt[40] = 17 // Next Header = UDP
				pkt[41] = 0  // Hdr Ext Len = 0 (means 8 bytes total)
				// 6 bytes of padding/options

				// UDP header
				binary.BigEndian.PutUint16(pkt[48:50], 1234) // Source port
				binary.BigEndian.PutUint16(pkt[50:52], 5678) // Dest port
				binary.BigEndian.PutUint16(pkt[52:54], 8)    // UDP length
				binary.BigEndian.PutUint16(pkt[54:56], 0)    // Checksum

				return pkt
			}(),
			expected: "IPv6 2001:db8::1:1234→2001:db8::2:5678 UDP | 0B",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := SummarizePacket(tt.packet)
			if result != tt.expected {
				t.Errorf("SummarizePacket() = %q, want %q", result, tt.expected)
			}
		})
	}
}
