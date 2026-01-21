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

func TestExtractDNSFromPacket_IPv4_ResponseWithARecord(t *testing.T) {
	clientIP := net.ParseIP("192.168.1.100")
	serverIP := net.ParseIP("8.8.8.8")
	resolvedIP := net.IPv4(93, 184, 216, 34)

	pkt := createIPv4DNSResponseWithAnswer(clientIP, serverIP, resolvedIP, 1) // type A

	qnames, ips, isQuery, dnsAddr, ok := ExtractDNSFromPacket(pkt)

	if !ok {
		t.Fatal("Expected ok=true for valid DNS response")
	}
	if isQuery {
		t.Error("Expected isQuery=false for DNS response")
	}
	if !dnsAddr.Equal(serverIP) {
		t.Errorf("Expected dnsAddr=%s, got %s", serverIP, dnsAddr)
	}
	if len(qnames) != 1 || qnames[0] != "www.example.com" {
		t.Errorf("Expected qnames=[www.example.com], got %v", qnames)
	}
	if len(ips) != 1 || !ips[0].Equal(resolvedIP) {
		t.Errorf("Expected ips=[%s], got %v", resolvedIP, ips)
	}
}

func TestExtractDNSFromPacket_IPv4_ResponseWithAAAARecord(t *testing.T) {
	clientIP := net.ParseIP("192.168.1.100")
	serverIP := net.ParseIP("8.8.8.8")
	resolvedIP := net.ParseIP("2606:2800:220:1:248:1893:25c8:1946")

	pkt := createIPv4DNSResponseWithAAAA(clientIP, serverIP, resolvedIP)

	qnames, ips, isQuery, _, ok := ExtractDNSFromPacket(pkt)

	if !ok {
		t.Fatal("Expected ok=true for valid DNS response with AAAA")
	}
	if isQuery {
		t.Error("Expected isQuery=false")
	}
	if len(qnames) != 1 || qnames[0] != "www.example.com" {
		t.Errorf("Expected qnames=[www.example.com], got %v", qnames)
	}
	if len(ips) != 1 || !ips[0].Equal(resolvedIP) {
		t.Errorf("Expected ips=[%s], got %v", resolvedIP, ips)
	}
}

func TestExtractDNSFromPacket_IPv4_ResponseWithMultipleAnswers(t *testing.T) {
	clientIP := net.ParseIP("192.168.1.100")
	serverIP := net.ParseIP("8.8.8.8")
	ip1 := net.IPv4(93, 184, 216, 34)
	ip2 := net.IPv4(93, 184, 216, 35)

	pkt := createIPv4DNSResponseWithMultipleA(clientIP, serverIP, []net.IP{ip1, ip2})

	_, ips, _, _, ok := ExtractDNSFromPacket(pkt)

	if !ok {
		t.Fatal("Expected ok=true")
	}
	if len(ips) != 2 {
		t.Fatalf("Expected 2 IPs, got %d", len(ips))
	}
	if !ips[0].Equal(ip1) || !ips[1].Equal(ip2) {
		t.Errorf("Expected IPs [%s, %s], got %v", ip1, ip2, ips)
	}
}

func TestExtractDNSFromPacket_FragmentedIPv4(t *testing.T) {
	pkt := createIPv4DNSPacket(net.ParseIP("192.168.1.1"), net.ParseIP("8.8.8.8"), 12345, 53, true)
	// Set MF (More Fragments) flag
	pkt[6] |= 0x20

	_, _, _, _, ok := ExtractDNSFromPacket(pkt)
	if ok {
		t.Error("Expected ok=false for fragmented packet")
	}
}

func TestExtractDNSFromPacket_NonFirstFragment(t *testing.T) {
	pkt := createIPv4DNSPacket(net.ParseIP("192.168.1.1"), net.ParseIP("8.8.8.8"), 12345, 53, true)
	// Set fragment offset to non-zero
	binary.BigEndian.PutUint16(pkt[6:8], 100)

	_, _, _, _, ok := ExtractDNSFromPacket(pkt)
	if ok {
		t.Error("Expected ok=false for non-first fragment")
	}
}

func TestExtractDNSFromPacket_TCPProtocol(t *testing.T) {
	pkt := createIPv4DNSPacket(net.ParseIP("192.168.1.1"), net.ParseIP("8.8.8.8"), 12345, 53, true)
	pkt[9] = 6 // TCP instead of UDP

	_, _, _, _, ok := ExtractDNSFromPacket(pkt)
	if ok {
		t.Error("Expected ok=false for TCP protocol")
	}
}

func TestExtractDNSFromPacket_EmptyPacket(t *testing.T) {
	_, _, _, _, ok := ExtractDNSFromPacket(nil)
	if ok {
		t.Error("Expected ok=false for nil packet")
	}

	_, _, _, _, ok = ExtractDNSFromPacket([]byte{})
	if ok {
		t.Error("Expected ok=false for empty packet")
	}
}

func TestReadDNSName_Simple(t *testing.T) {
	// "www.example.com" encoded
	msg := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}

	name, off, ok := readDNSName(msg, 0, 0)
	if !ok {
		t.Fatal("Expected ok=true")
	}
	if name != "www.example.com" {
		t.Errorf("Expected 'www.example.com', got '%s'", name)
	}
	if off != 17 {
		t.Errorf("Expected offset 17, got %d", off)
	}
}

func TestReadDNSName_SingleLabel(t *testing.T) {
	msg := []byte{7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0}

	name, off, ok := readDNSName(msg, 0, 0)
	if !ok {
		t.Fatal("Expected ok=true")
	}
	if name != "example" {
		t.Errorf("Expected 'example', got '%s'", name)
	}
	if off != 9 {
		t.Errorf("Expected offset 9, got %d", off)
	}
}

func TestReadDNSName_RootDomain(t *testing.T) {
	msg := []byte{0}

	name, off, ok := readDNSName(msg, 0, 0)
	if !ok {
		t.Fatal("Expected ok=true")
	}
	if name != "" {
		t.Errorf("Expected empty string for root, got '%s'", name)
	}
	if off != 1 {
		t.Errorf("Expected offset 1, got %d", off)
	}
}

func TestReadDNSName_Compression(t *testing.T) {
	// Message with compression pointer
	// At offset 0: "example.com" (13 bytes)
	// At offset 13: pointer to offset 0 (should read as "example.com")
	msg := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // offset 0-12: "example.com"
		0xC0, 0x00, // offset 13-14: pointer to offset 0
	}

	name, off, ok := readDNSName(msg, 13, 0)
	if !ok {
		t.Fatal("Expected ok=true")
	}
	if name != "example.com" {
		t.Errorf("Expected 'example.com', got '%s'", name)
	}
	if off != 15 {
		t.Errorf("Expected offset 15, got %d", off)
	}
}

func TestReadDNSName_CompressionWithPrefix(t *testing.T) {
	// "www" followed by pointer to "example.com"
	msg := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // offset 0-12: "example.com"
		3, 'w', 'w', 'w', 0xC0, 0x00, // offset 13-18: "www" + pointer to "example.com"
	}

	name, off, ok := readDNSName(msg, 13, 0)
	if !ok {
		t.Fatal("Expected ok=true")
	}
	if name != "www.example.com" {
		t.Errorf("Expected 'www.example.com', got '%s'", name)
	}
	if off != 19 {
		t.Errorf("Expected offset 19, got %d", off)
	}
}

func TestReadDNSName_DoubleCompression(t *testing.T) {
	// Chain: "mail" -> pointer to "www" -> pointer to "example.com"
	msg := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0, // offset 0-12: "example.com"
		3, 'w', 'w', 'w', 0xC0, 0x00, // offset 13-18: "www" + pointer
		4, 'm', 'a', 'i', 'l', 0xC0, 0x0D, // offset 19-25: "mail" + pointer to offset 13
	}

	name, off, ok := readDNSName(msg, 19, 0)
	if !ok {
		t.Fatal("Expected ok=true")
	}
	if name != "mail.www.example.com" {
		t.Errorf("Expected 'mail.www.example.com', got '%s'", name)
	}
	if off != 26 {
		t.Errorf("Expected offset 26, got %d", off)
	}
}

func TestReadDNSName_DepthLimit(t *testing.T) {
	// Create a self-referencing pointer (infinite loop)
	msg := []byte{0xC0, 0x00}

	_, _, ok := readDNSName(msg, 0, 0)
	if ok {
		t.Error("Expected ok=false for pointer loop")
	}
}

func TestReadDNSName_InvalidLabelType(t *testing.T) {
	// 0x40 and 0x80 are reserved label types
	msg := []byte{0x40, 'a', 'b', 'c', 0}

	_, _, ok := readDNSName(msg, 0, 0)
	if ok {
		t.Error("Expected ok=false for invalid label type 0x40")
	}
}

func TestReadDNSName_TruncatedLabel(t *testing.T) {
	// Label says 10 bytes but only 3 available
	msg := []byte{10, 'a', 'b', 'c'}

	_, _, ok := readDNSName(msg, 0, 0)
	if ok {
		t.Error("Expected ok=false for truncated label")
	}
}

func TestReadDNSName_TruncatedPointer(t *testing.T) {
	// Pointer needs 2 bytes but only 1 available
	msg := []byte{0xC0}

	_, _, ok := readDNSName(msg, 0, 0)
	if ok {
		t.Error("Expected ok=false for truncated pointer")
	}
}

func TestParseDNSMessage_TooShort(t *testing.T) {
	payload := make([]byte, 11) // less than 12 bytes header
	_, _, _, ok := parseDNSMessage(payload)
	if ok {
		t.Error("Expected ok=false for payload < 12 bytes")
	}
}

func TestParseDNSMessage_Query(t *testing.T) {
	payload := createDNSQueryPayload("test.example.org")

	qnames, ips, isQuery, ok := parseDNSMessage(payload)
	if !ok {
		t.Fatal("Expected ok=true")
	}
	if !isQuery {
		t.Error("Expected isQuery=true")
	}
	if len(qnames) != 1 || qnames[0] != "test.example.org" {
		t.Errorf("Expected qnames=[test.example.org], got %v", qnames)
	}
	if len(ips) != 0 {
		t.Error("Expected no IPs for query")
	}
}

func TestExtractDNSFromPacket_BufferReuse(t *testing.T) {
	clientIP := net.ParseIP("192.168.1.100")
	serverIP := net.ParseIP("8.8.8.8")
	resolvedIP := net.IPv4(93, 184, 216, 34)

	pkt := createIPv4DNSResponseWithAnswer(clientIP, serverIP, resolvedIP, 1)

	_, ips, _, dnsAddr, ok := ExtractDNSFromPacket(pkt)
	if !ok {
		t.Fatal("Expected ok=true")
	}

	// Save the returned values
	savedDNSAddr := dnsAddr.String()
	savedIP := ips[0].String()

	// Overwrite the packet buffer
	for i := range pkt {
		pkt[i] = 0xFF
	}

	// Verify the returned IPs are not affected (they should be copies)
	if dnsAddr.String() != savedDNSAddr {
		t.Errorf("dnsAddr changed after buffer modification: expected %s, got %s", savedDNSAddr, dnsAddr)
	}
	if ips[0].String() != savedIP {
		t.Errorf("resolved IP changed after buffer modification: expected %s, got %s", savedIP, ips[0])
	}
}

func TestExtractDNSFromPacket_IPv6_BufferReuse(t *testing.T) {
	clientIP := net.ParseIP("2001:db8::1")
	serverIP := net.ParseIP("2001:4860:4860::8888")

	pkt := createIPv6DNSPacket(clientIP, serverIP, 12345, 53, true)

	_, _, _, dnsAddr, ok := ExtractDNSFromPacket(pkt)
	if !ok {
		t.Fatal("Expected ok=true")
	}

	savedDNSAddr := dnsAddr.String()

	// Overwrite the packet buffer
	for i := range pkt {
		pkt[i] = 0xFF
	}

	if dnsAddr.String() != savedDNSAddr {
		t.Errorf("IPv6 dnsAddr changed after buffer modification: expected %s, got %s", savedDNSAddr, dnsAddr)
	}
}

func TestExtractDNSFromPacket_IPv6_WithHopByHopHeader(t *testing.T) {
	pkt := createIPv6DNSWithExtHeader(0, 8) // Hop-by-Hop, 8 bytes
	_, _, _, _, ok := ExtractDNSFromPacket(pkt)
	if !ok {
		t.Error("Expected ok=true for IPv6 with Hop-by-Hop extension header")
	}
}

func TestExtractDNSFromPacket_IPv6_WithRoutingHeader(t *testing.T) {
	pkt := createIPv6DNSWithExtHeader(43, 8) // Routing, 8 bytes
	_, _, _, _, ok := ExtractDNSFromPacket(pkt)
	if !ok {
		t.Error("Expected ok=true for IPv6 with Routing extension header")
	}
}

func TestExtractDNSFromPacket_IPv6_WithFragmentHeader(t *testing.T) {
	pkt := createIPv6DNSWithFragmentHeader(0, false) // offset=0, M=false (complete packet)
	_, _, _, _, ok := ExtractDNSFromPacket(pkt)
	if !ok {
		t.Error("Expected ok=true for IPv6 with Fragment header (complete packet)")
	}
}

func TestExtractDNSFromPacket_IPv6_FragmentedPacket(t *testing.T) {
	pkt := createIPv6DNSWithFragmentHeader(0, true) // offset=0, M=true (more fragments)
	_, _, _, _, ok := ExtractDNSFromPacket(pkt)
	if ok {
		t.Error("Expected ok=false for fragmented IPv6 packet")
	}
}

func TestExtractDNSFromPacket_IPv6_NonFirstFragment(t *testing.T) {
	pkt := createIPv6DNSWithFragmentHeader(8, false) // offset=8, non-first fragment
	_, _, _, _, ok := ExtractDNSFromPacket(pkt)
	if ok {
		t.Error("Expected ok=false for non-first IPv6 fragment")
	}
}

func TestExtractDNSFromPacket_SourcePort53(t *testing.T) {
	// DNS response from port 53
	pkt := createIPv4DNSPacket(net.ParseIP("8.8.8.8"), net.ParseIP("192.168.1.1"), 53, 12345, false)
	_, _, _, _, ok := ExtractDNSFromPacket(pkt)
	if !ok {
		t.Error("Expected ok=true for packet with source port 53")
	}
}

// Helper functions for creating test packets

func createIPv4DNSResponseWithAnswer(clientIP, serverIP, resolvedIP net.IP, qtype uint16) []byte {
	questionLen := 17 + 4 // "www.example.com" + QTYPE + QCLASS
	answerLen := 2 + 10 + 4 // pointer + TYPE/CLASS/TTL/RDLENGTH + RDATA
	dnsLen := 12 + questionLen + answerLen
	udpLen := 8 + dnsLen
	totalLen := 20 + udpLen

	pkt := make([]byte, totalLen)

	// IPv4 header
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[9] = 17
	copy(pkt[12:16], serverIP.To4())
	copy(pkt[16:20], clientIP.To4())

	// UDP header
	binary.BigEndian.PutUint16(pkt[20:22], 53)
	binary.BigEndian.PutUint16(pkt[22:24], 12345)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))

	// DNS header
	idx := 28
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 0x1234)   // ID
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 0x8180) // Flags: QR=1, RD=1, RA=1
	binary.BigEndian.PutUint16(pkt[idx+4:idx+6], 1)      // QDCOUNT
	binary.BigEndian.PutUint16(pkt[idx+6:idx+8], 1)      // ANCOUNT
	idx += 12

	// Question: www.example.com
	idx = writeDNSName(pkt, idx, "www.example.com")
	binary.BigEndian.PutUint16(pkt[idx:idx+2], qtype) // QTYPE
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 1)   // QCLASS
	idx += 4

	// Answer: pointer to question name + A record
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 0xC00C) // Pointer to offset 12
	idx += 2
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 1)    // TYPE = A
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 1)  // CLASS = IN
	binary.BigEndian.PutUint32(pkt[idx+4:idx+8], 300) // TTL
	binary.BigEndian.PutUint16(pkt[idx+8:idx+10], 4) // RDLENGTH
	idx += 10
	copy(pkt[idx:idx+4], resolvedIP.To4())

	return pkt
}

func createIPv4DNSResponseWithAAAA(clientIP, serverIP, resolvedIP net.IP) []byte {
	questionLen := 17 + 4
	answerLen := 2 + 10 + 16 // pointer + header + 16-byte IPv6
	dnsLen := 12 + questionLen + answerLen
	udpLen := 8 + dnsLen
	totalLen := 20 + udpLen

	pkt := make([]byte, totalLen)

	// IPv4 header
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[9] = 17
	copy(pkt[12:16], serverIP.To4())
	copy(pkt[16:20], clientIP.To4())

	// UDP header
	binary.BigEndian.PutUint16(pkt[20:22], 53)
	binary.BigEndian.PutUint16(pkt[22:24], 12345)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))

	// DNS header
	idx := 28
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 0x1234)
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 0x8180)
	binary.BigEndian.PutUint16(pkt[idx+4:idx+6], 1) // QDCOUNT
	binary.BigEndian.PutUint16(pkt[idx+6:idx+8], 1) // ANCOUNT
	idx += 12

	// Question
	idx = writeDNSName(pkt, idx, "www.example.com")
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 28) // QTYPE = AAAA
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 1)
	idx += 4

	// Answer
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 0xC00C)
	idx += 2
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 28)   // TYPE = AAAA
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 1)  // CLASS
	binary.BigEndian.PutUint32(pkt[idx+4:idx+8], 300) // TTL
	binary.BigEndian.PutUint16(pkt[idx+8:idx+10], 16) // RDLENGTH
	idx += 10
	copy(pkt[idx:idx+16], resolvedIP.To16())

	return pkt
}

func createIPv4DNSResponseWithMultipleA(clientIP, serverIP net.IP, resolvedIPs []net.IP) []byte {
	questionLen := 17 + 4
	answerLen := len(resolvedIPs) * (2 + 10 + 4)
	dnsLen := 12 + questionLen + answerLen
	udpLen := 8 + dnsLen
	totalLen := 20 + udpLen

	pkt := make([]byte, totalLen)

	// IPv4 header
	pkt[0] = 0x45
	binary.BigEndian.PutUint16(pkt[2:4], uint16(totalLen))
	pkt[9] = 17
	copy(pkt[12:16], serverIP.To4())
	copy(pkt[16:20], clientIP.To4())

	// UDP header
	binary.BigEndian.PutUint16(pkt[20:22], 53)
	binary.BigEndian.PutUint16(pkt[22:24], 12345)
	binary.BigEndian.PutUint16(pkt[24:26], uint16(udpLen))

	// DNS header
	idx := 28
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 0x1234)
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 0x8180)
	binary.BigEndian.PutUint16(pkt[idx+4:idx+6], 1)
	binary.BigEndian.PutUint16(pkt[idx+6:idx+8], uint16(len(resolvedIPs)))
	idx += 12

	// Question
	idx = writeDNSName(pkt, idx, "www.example.com")
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 1)
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 1)
	idx += 4

	// Answers
	for _, ip := range resolvedIPs {
		binary.BigEndian.PutUint16(pkt[idx:idx+2], 0xC00C)
		idx += 2
		binary.BigEndian.PutUint16(pkt[idx:idx+2], 1)
		binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 1)
		binary.BigEndian.PutUint32(pkt[idx+4:idx+8], 300)
		binary.BigEndian.PutUint16(pkt[idx+8:idx+10], 4)
		idx += 10
		copy(pkt[idx:idx+4], ip.To4())
		idx += 4
	}

	return pkt
}

func createIPv6DNSWithExtHeader(nextHeader byte, extLen int) []byte {
	udpLen := 8 + 12 + 22
	payloadLen := extLen + udpLen
	totalLen := 40 + payloadLen
	pkt := make([]byte, totalLen)

	// IPv6 header
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(payloadLen))
	pkt[6] = nextHeader // Next header = extension header type
	pkt[7] = 64
	copy(pkt[8:24], net.ParseIP("2001:db8::1").To16())
	copy(pkt[24:40], net.ParseIP("2001:4860:4860::8888").To16())

	// Extension header
	idx := 40
	pkt[idx] = 17                    // Next = UDP
	pkt[idx+1] = byte(extLen/8 - 1)  // Length in 8-byte units minus 1
	idx += extLen

	// UDP header
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 12345)
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 53)
	binary.BigEndian.PutUint16(pkt[idx+4:idx+6], uint16(udpLen))
	idx += 8

	// DNS header
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 0x1234)
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 0x0100)
	binary.BigEndian.PutUint16(pkt[idx+4:idx+6], 1)
	idx += 12

	// Question
	idx = writeDNSName(pkt, idx, "www.example.com")
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 1)
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 1)

	return pkt
}

func createIPv6DNSWithFragmentHeader(fragOffset uint16, moreFragments bool) []byte {
	udpLen := 8 + 12 + 22
	payloadLen := 8 + udpLen // Fragment header is 8 bytes
	totalLen := 40 + payloadLen
	pkt := make([]byte, totalLen)

	// IPv6 header
	pkt[0] = 0x60
	binary.BigEndian.PutUint16(pkt[4:6], uint16(payloadLen))
	pkt[6] = 44 // Next header = Fragment
	pkt[7] = 64
	copy(pkt[8:24], net.ParseIP("2001:db8::1").To16())
	copy(pkt[24:40], net.ParseIP("2001:4860:4860::8888").To16())

	// Fragment header (8 bytes)
	idx := 40
	pkt[idx] = 17 // Next = UDP
	pkt[idx+1] = 0 // Reserved
	fragOffFlags := (fragOffset & 0xFFF8)
	if moreFragments {
		fragOffFlags |= 0x0001
	}
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], fragOffFlags)
	idx += 8

	// UDP header
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 12345)
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 53)
	binary.BigEndian.PutUint16(pkt[idx+4:idx+6], uint16(udpLen))
	idx += 8

	// DNS header
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 0x1234)
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 0x0100)
	binary.BigEndian.PutUint16(pkt[idx+4:idx+6], 1)
	idx += 12

	// Question
	idx = writeDNSName(pkt, idx, "www.example.com")
	binary.BigEndian.PutUint16(pkt[idx:idx+2], 1)
	binary.BigEndian.PutUint16(pkt[idx+2:idx+4], 1)

	return pkt
}

func createDNSQueryPayload(domain string) []byte {
	nameLen := len(domain) + 2 // labels + null terminator
	payload := make([]byte, 12+nameLen+4)

	// DNS header
	binary.BigEndian.PutUint16(payload[0:2], 0x1234)  // ID
	binary.BigEndian.PutUint16(payload[2:4], 0x0100)  // Flags: QR=0
	binary.BigEndian.PutUint16(payload[4:6], 1)       // QDCOUNT
	binary.BigEndian.PutUint16(payload[6:8], 0)       // ANCOUNT

	idx := writeDNSName(payload, 12, domain)
	binary.BigEndian.PutUint16(payload[idx:idx+2], 1)   // QTYPE
	binary.BigEndian.PutUint16(payload[idx+2:idx+4], 1) // QCLASS

	return payload
}

func writeDNSName(buf []byte, off int, name string) int {
	if name == "" {
		buf[off] = 0
		return off + 1
	}
	labels := splitDomain(name)
	for _, label := range labels {
		buf[off] = byte(len(label))
		off++
		copy(buf[off:], label)
		off += len(label)
	}
	buf[off] = 0
	return off + 1
}

func splitDomain(name string) []string {
	var labels []string
	start := 0
	for i := range len(name) {
		if name[i] == '.' {
			labels = append(labels, name[start:i])
			start = i + 1
		}
	}
	if start < len(name) {
		labels = append(labels, name[start:])
	}
	return labels
}

// Benchmarks

func BenchmarkExtractDNSFromPacket_IPv4Query(b *testing.B) {
	pkt := createIPv4DNSPacket(net.ParseIP("192.168.1.1"), net.ParseIP("8.8.8.8"), 12345, 53, true)
	b.ResetTimer()
	for range b.N {
		ExtractDNSFromPacket(pkt)
	}
}

func BenchmarkExtractDNSFromPacket_IPv4Response(b *testing.B) {
	pkt := createIPv4DNSResponseWithAnswer(
		net.ParseIP("192.168.1.1"),
		net.ParseIP("8.8.8.8"),
		net.IPv4(93, 184, 216, 34),
		1,
	)
	b.ResetTimer()
	for range b.N {
		ExtractDNSFromPacket(pkt)
	}
}

func BenchmarkExtractDNSFromPacket_IPv6Query(b *testing.B) {
	pkt := createIPv6DNSPacket(net.ParseIP("2001:db8::1"), net.ParseIP("2001:4860:4860::8888"), 12345, 53, true)
	b.ResetTimer()
	for range b.N {
		ExtractDNSFromPacket(pkt)
	}
}

func BenchmarkReadDNSName_Simple(b *testing.B) {
	msg := []byte{3, 'w', 'w', 'w', 7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0}
	b.ResetTimer()
	for range b.N {
		readDNSName(msg, 0, 0)
	}
}

func BenchmarkReadDNSName_Compressed(b *testing.B) {
	msg := []byte{
		7, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 3, 'c', 'o', 'm', 0,
		3, 'w', 'w', 'w', 0xC0, 0x00,
	}
	b.ResetTimer()
	for range b.N {
		readDNSName(msg, 13, 0)
	}
}

func BenchmarkParseDNSMessage_Query(b *testing.B) {
	payload := createDNSQueryPayload("www.example.com")
	b.ResetTimer()
	for range b.N {
		parseDNSMessage(payload)
	}
}
