package ip

import (
	"encoding/binary"
	"net"
	"testing"
)

// Helper function to create a minimal IPv4 DNS packet
func createIPv4DNSPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, isQuery bool) []byte {
	// IPv4 header (20 bytes) + UDP header (8 bytes) + minimal DNS (12 bytes) + question (22 bytes)
	totalLen := 20 + 8 + 12 + 22
	pkt := make([]byte, totalLen)

	// IPv4 header
	pkt[0] = 0x45                                          // Version 4, IHL 5 (20 bytes)
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen)) // Total length
	pkt[9] = 17                                            // Protocol = UDP
	copy(pkt[12:16], srcIP.To4())                          // Source IP
	copy(pkt[16:20], dstIP.To4())                          // Destination IP

	// UDP header
	udpLen := 8 + 12 + 22
	binary.BigEndian.PutUint16(pkt[20:22], srcPort)        // Source port
	binary.BigEndian.PutUint16(pkt[22:24], dstPort)        // Destination port
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen)) // UDP length

	// DNS header (12 bytes)
	binary.BigEndian.PutUint16(pkt[28:30], 0x1234) // Transaction ID
	if isQuery {
		binary.BigEndian.PutUint16(pkt[30:32], 0x0100) // Flags: QR=0 (query), RD=1
	} else {
		binary.BigEndian.PutUint16(pkt[30:32], 0x8180) // Flags: QR=1 (response), RD=1, RA=1
	}
	binary.BigEndian.PutUint16(pkt[32:34], 1) // Question count
	binary.BigEndian.PutUint16(pkt[34:36], 0) // Answer count
	binary.BigEndian.PutUint16(pkt[36:38], 0) // Authority count
	binary.BigEndian.PutUint16(pkt[38:40], 0) // Additional count

	// Minimal question: "\x03www\x07example\x03com\x00" + QTYPE (A) + QCLASS (IN)
	idx := 40
	pkt[idx] = 3 // length of "www"
	idx++
	copy(pkt[idx:idx+3], []byte("www"))
	idx += 3
	pkt[idx] = 7 // length of "example"
	idx++
	copy(pkt[idx:idx+7], []byte("example"))
	idx += 7
	pkt[idx] = 3 // length of "com"
	idx++
	copy(pkt[idx:idx+3], []byte("com"))
	idx += 3
	pkt[idx] = 0 // end of name
	idx++
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 1) // QTYPE = A
	idx += 2
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 1) // QCLASS = IN

	return pkt
}

// Helper function to create a minimal IPv6 DNS packet
func createIPv6DNSPacket(srcIP, dstIP net.IP, srcPort, dstPort uint16, isQuery bool) []byte {
	// IPv6 header (40 bytes) + UDP header (8 bytes) + minimal DNS (12 bytes) + question (22 bytes)
	totalLen := 40 + 8 + 12 + 22
	pkt := make([]byte, totalLen)

	// IPv6 header
	pkt[0] = 0x60 // Version 6
	payloadLen := 8 + 12 + 22
	binary.BigEndian.PutUint16(pkt[4:6], uint16(payloadLen)) // Payload length (UDP + DNS)
	pkt[6] = 17                                              // Next header = UDP
	pkt[7] = 64                                              // Hop limit
	copy(pkt[8:24], srcIP.To16())                            // Source IP
	copy(pkt[24:40], dstIP.To16())                           // Destination IP

	// UDP header
	udpLen := 8 + 12 + 22
	binary.BigEndian.PutUint16(pkt[40:42], srcPort)        // Source port
	binary.BigEndian.PutUint16(pkt[42:44], dstPort)        // Destination port
	binary.BigEndian.PutUint16(pkt[44:46], uint16(udpLen)) // UDP length

	// DNS header (12 bytes)
	binary.BigEndian.PutUint16(pkt[48:50], 0x1234) // Transaction ID
	if isQuery {
		binary.BigEndian.PutUint16(pkt[50:52], 0x0100) // Flags: QR=0 (query), RD=1
	} else {
		binary.BigEndian.PutUint16(pkt[50:52], 0x8180) // Flags: QR=1 (response), RD=1, RA=1
	}
	binary.BigEndian.PutUint16(pkt[52:54], 1) // Question count
	binary.BigEndian.PutUint16(pkt[54:56], 0) // Answer count
	binary.BigEndian.PutUint16(pkt[56:58], 0) // Authority count
	binary.BigEndian.PutUint16(pkt[58:60], 0) // Additional count

	// Minimal question: "\x03www\x07example\x03com\x00" + QTYPE (A) + QCLASS (IN)
	idx := 60
	pkt[idx] = 3 // length of "www"
	idx++
	copy(pkt[idx:idx+3], []byte("www"))
	idx += 3
	pkt[idx] = 7 // length of "example"
	idx++
	copy(pkt[idx:idx+7], []byte("example"))
	idx += 7
	pkt[idx] = 3 // length of "com"
	idx++
	copy(pkt[idx:idx+3], []byte("com"))
	idx += 3
	pkt[idx] = 0 // end of name
	idx++
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 1) // QTYPE = A
	idx += 2
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 1) // QCLASS = IN

	return pkt
}

func TestExtractDNSFromPacket_IPv4_Query(t *testing.T) {
	clientIP := net.ParseIP("192.168.1.100")
	serverIP := net.ParseIP("8.8.8.8")

	// Create IPv4 DNS query packet (client -> server)
	pkt := createIPv4DNSPacket(clientIP, serverIP, 12345, 53, true)

	_, ips, isQuery, dnsAddr, ok := ExtractDNSFromPacket(pkt)

	if !ok {
		t.Fatal("Expected ok=true for valid DNS query packet")
	}

	if !isQuery {
		t.Error("Expected isQuery=true for DNS query packet")
	}

	if !dnsAddr.Equal(serverIP) {
		t.Errorf("Expected dnsAddr=%s (destination), got %s", serverIP, dnsAddr)
	}

	// For queries, we don't expect resolved IPs
	if len(ips) != 0 {
		t.Error("Expected empty IP list for DNS query")
	}
}

func TestExtractDNSFromPacket_IPv4_Response(t *testing.T) {
	clientIP := net.ParseIP("192.168.1.100")
	serverIP := net.ParseIP("8.8.8.8")

	// Create IPv4 DNS response packet (server -> client)
	pkt := createIPv4DNSPacket(serverIP, clientIP, 53, 12345, false)

	_, _, isQuery, dnsAddr, ok := ExtractDNSFromPacket(pkt)

	if !ok {
		t.Fatal("Expected ok=true for valid DNS response packet")
	}

	if isQuery {
		t.Error("Expected isQuery=false for DNS response packet")
	}

	if !dnsAddr.Equal(serverIP) {
		t.Errorf("Expected dnsAddr=%s (source), got %s", serverIP, dnsAddr)
	}
}

func TestExtractDNSFromPacket_IPv6_Query(t *testing.T) {
	clientIP := net.ParseIP("2001:db8::1")
	serverIP := net.ParseIP("2001:4860:4860::8888")

	// Create IPv6 DNS query packet (client -> server)
	pkt := createIPv6DNSPacket(clientIP, serverIP, 12345, 53, true)

	_, _, isQuery, dnsAddr, ok := ExtractDNSFromPacket(pkt)

	if !ok {
		t.Fatal("Expected ok=true for valid IPv6 DNS query packet")
	}

	if !isQuery {
		t.Error("Expected isQuery=true for DNS query packet")
	}

	if !dnsAddr.Equal(serverIP) {
		t.Errorf("Expected dnsAddr=%s (destination), got %s", serverIP, dnsAddr)
	}
}

func TestExtractDNSFromPacket_IPv6_Response(t *testing.T) {
	clientIP := net.ParseIP("2001:db8::1")
	serverIP := net.ParseIP("2001:4860:4860::8888")

	// Create IPv6 DNS response packet (server -> client)
	pkt := createIPv6DNSPacket(serverIP, clientIP, 53, 12345, false)

	_, _, isQuery, dnsAddr, ok := ExtractDNSFromPacket(pkt)

	if !ok {
		t.Fatal("Expected ok=true for valid IPv6 DNS response packet")
	}

	if isQuery {
		t.Error("Expected isQuery=false for DNS response packet")
	}

	if !dnsAddr.Equal(serverIP) {
		t.Errorf("Expected dnsAddr=%s (source), got %s", serverIP, dnsAddr)
	}
}

func TestExtractDNSFromPacket_InvalidPacket(t *testing.T) {
	// Test with invalid packet
	invalidPkt := []byte{0x99, 0x01, 0x02}

	qnames, ips, _, dnsAddr, ok := ExtractDNSFromPacket(invalidPkt)

	if ok {
		t.Error("Expected ok=false for invalid packet")
	}

	if len(qnames) != 0 {
		t.Error("Expected empty qnames for invalid packet")
	}

	if len(ips) != 0 {
		t.Error("Expected empty IPs for invalid packet")
	}

	if dnsAddr != nil {
		t.Error("Expected nil dnsAddr for invalid packet")
	}
}

func TestExtractDNSFromPacket_NonDNSPacket(t *testing.T) {
	// Create IPv4 UDP packet but not on port 53
	pkt := make([]byte, 32)
	pkt[0] = 0x45                            // Version 4, IHL 5
	binary.BigEndian.PutUint16(pkt[2:4], 32) // Total length
	pkt[9] = 17                              // Protocol = UDP
	copy(pkt[12:16], net.ParseIP("192.168.1.1").To4())
	copy(pkt[16:20], net.ParseIP("192.168.1.2").To4())

	// UDP header with non-DNS ports
	binary.BigEndian.PutUint16(pkt[20:22], 12345) // Source port
	binary.BigEndian.PutUint16(pkt[22:24], 80)    // Destination port (not 53)
	binary.BigEndian.PutUint16(pkt[24:26], 12)    // UDP length

	_, _, _, dnsAddr, ok := ExtractDNSFromPacket(pkt)

	if ok {
		t.Error("Expected ok=false for non-DNS packet")
	}

	if dnsAddr != nil {
		t.Error("Expected nil dnsAddr for non-DNS packet")
	}
}
