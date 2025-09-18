package ip

import (
	"encoding/binary"
	"net"
)

// RewriteIPV4Dest rewrites an IPv4+UDP DNS packet to ipStr:53 and recalculates checksums.
func RewriteIPV4Dest(pkt []byte, ipStr string) bool {
	// Validate IP and IPv4 header
	ip := net.ParseIP(ipStr)
	v4 := ip.To4()
	if v4 == nil {
		return false
	}
	if len(pkt) < 20 || (pkt[0]>>4) != 4 {
		return false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return false
	}
	// Only handle UDP
	if pkt[9] != 17 {
		return false
	}

	udpOff := ihl
	udpLen := int(binary.BigEndian.Uint16(pkt[udpOff+4 : udpOff+6]))
	if udpLen < 8 || len(pkt) < udpOff+udpLen {
		return false
	}

	// Set dest IPv4
	copy(pkt[16:20], v4)
	// Set dest port to 53
	binary.BigEndian.PutUint16(pkt[udpOff+2:udpOff+4], 53)

	// Recalculate IPv4 header checksum
	updateIPv4HeaderChecksum(pkt[:ihl])

	// Recalculate UDP checksum (IPv4)
	updateUDPChecksumIPv4(pkt, ihl, udpLen)

	return true
}

// RewriteIPV6Dest rewrites an IPv6+UDP DNS packet to ipStr:53 and recalculates checksums.
func RewriteIPV6Dest(pkt []byte, ipStr string) bool {
	// Validate IP and IPv6 header
	ip := net.ParseIP(ipStr)
	v6 := ip.To16()
	// Exclude IPv4-mapped addresses (ensure true IPv6)
	if v6 == nil || ip.To4() != nil {
		return false
	}
	if len(pkt) < 40 || (pkt[0]>>4) != 6 {
		return false
	}
	if pkt[6] != 17 { // Next Header: UDP
		return false
	}

	const ipv6HeaderLen = 40
	udpOff := ipv6HeaderLen
	if len(pkt) < udpOff+8 {
		return false
	}
	udpLen := int(binary.BigEndian.Uint16(pkt[udpOff+4 : udpOff+6]))
	if udpLen < 8 || len(pkt) < udpOff+udpLen {
		return false
	}

	// Set dest IPv6
	copy(pkt[24:40], v6)
	// Set dest port to 53
	binary.BigEndian.PutUint16(pkt[udpOff+2:udpOff+4], 53)

	// Recalculate UDP checksum for IPv6 (mandatory)
	updateUDPChecksumIPv6(pkt, udpLen)

	return true
}

func updateIPv4HeaderChecksum(hdr []byte) {
	if len(hdr) < 20 {
		return
	}
	// Zero checksum field
	hdr[10], hdr[11] = 0, 0
	sum := uint32(0)
	for i := 0; i+1 < len(hdr); i += 2 {
		sum += uint32(binary.BigEndian.Uint16(hdr[i : i+2]))
	}
	// Fold
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	cs := ^uint16(sum)
	binary.BigEndian.PutUint16(hdr[10:12], cs)
}

func updateUDPChecksumIPv4(pkt []byte, ipHeaderLen int, udpLen int) {
	udpOff := ipHeaderLen
	if len(pkt) < udpOff+udpLen || udpLen < 8 {
		return
	}
	// Zero UDP checksum field
	pkt[udpOff+6], pkt[udpOff+7] = 0, 0

	sum := uint32(0)
	// Pseudo-header: src IP (4), dst IP (4), zero(1)+proto(1), UDP len(2)
	// Src IP
	sum += uint32(binary.BigEndian.Uint16(pkt[12:14]))
	sum += uint32(binary.BigEndian.Uint16(pkt[14:16]))
	// Dst IP
	sum += uint32(binary.BigEndian.Uint16(pkt[16:18]))
	sum += uint32(binary.BigEndian.Uint16(pkt[18:20]))
	// Protocol and UDP length
	sum += uint32(17) // protocol UDP
	sum += uint32(udpLen)

	// UDP header + payload
	for i := udpOff; i+1 < udpOff+udpLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	// If odd length, pad last byte
	if udpLen%2 == 1 {
		last := pkt[udpOff+udpLen-1]
		sum += uint32(last) << 8
	}

	// Fold
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	cs := ^uint16(sum)
	// For IPv4 UDP, 0 means no checksum; we keep computed value
	binary.BigEndian.PutUint16(pkt[udpOff+6:udpOff+8], cs)
}

func updateUDPChecksumIPv6(pkt []byte, udpLen int) {
	const ipv6HeaderLen = 40
	udpOff := ipv6HeaderLen
	if len(pkt) < udpOff+udpLen || udpLen < 8 {
		return
	}

	// Zero UDP checksum field
	pkt[udpOff+6], pkt[udpOff+7] = 0, 0

	sum := uint32(0)
	// Pseudo-header for IPv6: src(16) + dst(16) + UDP len(4) + zeros(3) + next header(1)
	// Source Address
	for i := 8; i < 24; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	// Destination Address
	for i := 24; i < 40; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	// UDP Length (32-bit)
	sum += uint32(udpLen >> 16)
	sum += uint32(udpLen & 0xFFFF)
	// Next Header (UDP = 17)
	sum += uint32(17)

	// UDP header + payload
	for i := udpOff; i+1 < udpOff+udpLen; i += 2 {
		sum += uint32(binary.BigEndian.Uint16(pkt[i : i+2]))
	}
	// If odd length, pad last byte
	if udpLen%2 == 1 {
		last := pkt[udpOff+udpLen-1]
		sum += uint32(last) << 8
	}

	// Fold
	for (sum >> 16) != 0 {
		sum = (sum & 0xFFFF) + (sum >> 16)
	}
	cs := ^uint16(sum)
	if cs == 0 {
		// For IPv6, checksum cannot be 0; use 0xFFFF when computed zero
		cs = 0xFFFF
	}
	binary.BigEndian.PutUint16(pkt[udpOff+6:udpOff+8], cs)
}
