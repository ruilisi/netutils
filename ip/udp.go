package ip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
)

// ExtractUDPPayload extracts the UDP payload and addressing information from a raw IP packet (IPv4 or IPv6)
// Returns: payload, srcIP, srcPort, dstIP, dstPort, error
func ExtractUDPPayload(packet []byte) ([]byte, net.IP, uint16, net.IP, uint16, error) {
	if len(packet) < 1 {
		return nil, nil, 0, nil, 0, errors.New("packet too short")
	}

	ipVersion := packet[0] >> 4
	var ipHeaderLen int
	var srcIP, dstIP net.IP

	switch ipVersion {
	case 4: // IPv4
		if len(packet) < 20 {
			return nil, nil, 0, nil, 0, errors.New("packet too short for IPv4 header")
		}
		// Get IP header length (in 32-bit words)
		ipHeaderLen = int(packet[0]&0x0F) << 2
		if ipHeaderLen < 20 {
			return nil, nil, 0, nil, 0, errors.New("invalid IPv4 header length")
		}
		// Ensure packet is at least as long as the IP header
		if len(packet) < ipHeaderLen {
			return nil, nil, 0, nil, 0, errors.New("packet shorter than IP header length")
		}
		// Verify this is a UDP packet (protocol field at byte 9)
		if packet[9] != 17 {
			return nil, nil, 0, nil, 0, fmt.Errorf("not a UDP packet: protocol %d", packet[9])
		}
		// Extract source and destination IPs (IPv4)
		srcIP = net.IP(packet[12:16])
		dstIP = net.IP(packet[16:20])
	case 6: // IPv6 - fixed 40 byte header
		if len(packet) < 40 {
			return nil, nil, 0, nil, 0, errors.New("packet too short for IPv6 header")
		}
		ipHeaderLen = 40
		// Verify this is a UDP packet (Next Header field at byte 6)
		if packet[6] != 17 {
			return nil, nil, 0, nil, 0, fmt.Errorf("not a UDP packet: next header %d", packet[6])
		}
		// Extract source and destination IPs (IPv6)
		srcIP = net.IP(packet[8:24])
		dstIP = net.IP(packet[24:40])
		// TODO: handle extension headers if needed
	default:
		return nil, nil, 0, nil, 0, fmt.Errorf("unsupported IP version: %d", ipVersion)
	}

	if len(packet) < ipHeaderLen+8 {
		return nil, nil, 0, nil, 0, errors.New("packet too short for UDP header")
	}

	// Extract UDP ports from UDP header
	udpHeader := packet[ipHeaderLen : ipHeaderLen+8]
	srcPort := binary.BigEndian.Uint16(udpHeader[0:2])
	dstPort := binary.BigEndian.Uint16(udpHeader[2:4])

	// UDP payload starts after IP header + UDP header (8 bytes)
	payloadOffset := ipHeaderLen + 8
	if len(packet) <= payloadOffset {
		return []byte{}, srcIP, srcPort, dstIP, dstPort, nil
	}

	return packet[payloadOffset:], srcIP, srcPort, dstIP, dstPort, nil
}

// BuildIPv4UDPPacket constructs an IPv4 UDP packet
func BuildIPv4UDPPacket(localAddr *net.UDPAddr, srcAddr *net.UDPAddr, payload []byte) []byte {
	// IP header: 20 bytes (IPv4)
	// UDP header: 8 bytes
	totalLen := 20 + 8 + len(payload)
	packet := make([]byte, totalLen)

	// Normalize IPs to IPv4 format (4 bytes) to ensure proper checksum calculation
	srcIPv4 := srcAddr.IP.To4()
	dstIPv4 := localAddr.IP.To4()

	// Build minimal IPv4 header
	packet[0] = 0x45 // Version 4, header length 5 (20 bytes)
	packet[1] = 0x00 // TOS

	// Update IP header
	binary.BigEndian.PutUint16(packet[2:4], uint16(totalLen))      // Total length
	packet[8] = 255                                                // TTL
	packet[9] = 17                                                 // Protocol: UDP
	binary.BigEndian.PutUint32(packet[12:16], ipToUint32(srcIPv4)) // Source IP
	binary.BigEndian.PutUint32(packet[16:20], ipToUint32(dstIPv4)) // Dest IP

	// Calculate IP header checksum
	binary.BigEndian.PutUint16(packet[10:12], checksumIPv4(packet[:20]))

	// Build UDP header (offset 20)
	binary.BigEndian.PutUint16(packet[20:22], uint16(srcAddr.Port))   // Source port
	binary.BigEndian.PutUint16(packet[22:24], uint16(localAddr.Port)) // Dest port
	binary.BigEndian.PutUint16(packet[24:26], uint16(8+len(payload))) // UDP length
	binary.BigEndian.PutUint16(packet[26:28], 0)                      // Checksum placeholder

	// Copy payload
	copy(packet[28:], payload)

	// Calculate UDP checksum using normalized IPv4 addresses
	binary.BigEndian.PutUint16(packet[26:28], checksumUDP(srcIPv4, dstIPv4, packet[20:]))

	return packet
}

// BuildIPv6UDPPacket constructs an IPv6 UDP packet
func BuildIPv6UDPPacket(localAddr *net.UDPAddr, srcAddr *net.UDPAddr, payload []byte) []byte {
	// IPv6 header: 40 bytes
	// UDP header: 8 bytes
	totalLen := 40 + 8 + len(payload)
	packet := make([]byte, totalLen)

	// Build IPv6 header
	packet[0] = 0x60                                                // Version 6
	binary.BigEndian.PutUint16(packet[4:6], uint16(8+len(payload))) // Payload length (UDP header + data)
	packet[6] = 17                                                  // Next header: UDP
	packet[7] = 255                                                 // Hop limit
	copy(packet[8:24], srcAddr.IP.To16())                           // Source IP (16 bytes)
	copy(packet[24:40], localAddr.IP.To16())                        // Dest IP (16 bytes)

	// Build UDP header (offset 40)
	binary.BigEndian.PutUint16(packet[40:42], uint16(srcAddr.Port))   // Source port
	binary.BigEndian.PutUint16(packet[42:44], uint16(localAddr.Port)) // Dest port
	binary.BigEndian.PutUint16(packet[44:46], uint16(8+len(payload))) // UDP length
	binary.BigEndian.PutUint16(packet[46:48], 0)                      // Checksum placeholder

	// Copy payload
	copy(packet[48:], payload)

	// Calculate UDP checksum (mandatory for IPv6)
	binary.BigEndian.PutUint16(packet[46:48], checksumUDP(srcAddr.IP.To16(), localAddr.IP.To16(), packet[40:]))

	return packet
}

// ipToUint32 converts an IPv4 address to uint32 (network byte order)
func ipToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// isIPv6 checks if an IP address is IPv6
func isIPv6(ip net.IP) bool {
	return ip.To4() == nil && len(ip) == net.IPv6len
}

// checksumIPv4 calculates the IPv4 header checksum.
//
// Reference: RFC 791 - Internet Protocol, Section 3.1
// https://datatracker.ietf.org/doc/html/rfc791#section-3.1
//
// The checksum algorithm:
//  1. Set the checksum field to zero
//  2. Sum all 16-bit words in the header
//  3. Add any carry bits to the sum (ones' complement addition)
//  4. Take the ones' complement of the result
//
// The checksum is calculated over the entire IP header (normally 20 bytes).
// This is a 16-bit ones' complement of the ones' complement sum of all 16-bit
// words in the header. For purposes of computing the checksum, the value of
// the checksum field itself is zero.
//
// Important: The IP header checksum does NOT cover the data payload, only the
// IP header itself. This differs from UDP/TCP checksums which cover both header
// and data.
func checksumIPv4(header []byte) uint16 {
	var sum uint32
	for i := 0; i < len(header); i += 2 {
		if i == 10 { // Skip checksum field itself
			continue
		}
		sum += uint32(binary.BigEndian.Uint16(header[i : i+2]))
	}
	// Add carry
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	return ^uint16(sum)
}

// checksumUDP calculates the UDP checksum using a pseudo-header.
//
// References:
//   - RFC 768 - User Datagram Protocol (UDP for IPv4)
//     https://datatracker.ietf.org/doc/html/rfc768
//   - RFC 2460 - Internet Protocol, Version 6 (IPv6) Specification, Section 8.1
//     https://datatracker.ietf.org/doc/html/rfc2460#section-8.1
//   - RFC 8200 - Internet Protocol, Version 6 (IPv6) Specification (updates RFC 2460)
//     https://datatracker.ietf.org/doc/html/rfc8200
//
// The UDP checksum is calculated over three parts:
//  1. A pseudo-header (different for IPv4 vs IPv6)
//  2. The UDP header
//  3. The UDP data (payload)
//
// IPv4 Pseudo-Header (12 bytes, from RFC 768):
//   +--------+--------+--------+--------+
//   |       Source Address (4 bytes)   |
//   +--------+--------+--------+--------+
//   |     Destination Address (4 bytes)|
//   +--------+--------+--------+--------+
//   |  zero  |Protocol|   UDP Length    |
//   +--------+--------+--------+--------+
//   Where: Protocol = 17 (UDP)
//
// IPv6 Pseudo-Header (40 bytes, from RFC 2460):
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                         Source Address                        +
//   |                          (16 bytes)                           |
//   +                                                               +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                                                               |
//   +                      Destination Address                      +
//   |                          (16 bytes)                           |
//   +                                                               +
//   |                                                               |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                   UDP Length (4 bytes)                        |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   |                  zeros (3 bytes)     | Next Header (1 byte)   |
//   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
//   Where: Next Header = 17 (UDP)
//
// Checksum Algorithm (same for both IPv4 and IPv6):
//  1. Set the UDP checksum field to zero
//  2. Compute the 16-bit ones' complement sum of the pseudo-header,
//     UDP header, and UDP data
//  3. If the computed checksum is zero, transmit 0xFFFF (all ones)
//  4. Otherwise, transmit the computed checksum
//
// Note: For IPv4, UDP checksum is optional (can be 0). For IPv6, UDP checksum
// is MANDATORY and must be calculated and verified.
//
// Parameters:
//   - srcIP: Source IP address (must be 4 bytes for IPv4, 16 bytes for IPv6)
//   - dstIP: Destination IP address (must be 4 bytes for IPv4, 16 bytes for IPv6)
//   - udpSegment: Complete UDP packet including header and data
//
// Returns: The calculated UDP checksum (0xFFFF if the calculated value is 0)
func checksumUDP(srcIP, dstIP net.IP, udpSegment []byte) uint16 {
	var sum uint32

	// Pseudo-header for IPv4 (12 bytes) or IPv6 (40 bytes)
	if len(srcIP) == 4 {
		// IPv4 pseudo-header
		sum += uint32(binary.BigEndian.Uint16(srcIP[0:2]))
		sum += uint32(binary.BigEndian.Uint16(srcIP[2:4]))
		sum += uint32(binary.BigEndian.Uint16(dstIP[0:2]))
		sum += uint32(binary.BigEndian.Uint16(dstIP[2:4]))
		sum += uint32(17) // Protocol: UDP
		sum += uint32(len(udpSegment))
	} else {
		// IPv6 pseudo-header
		for i := 0; i < 16; i += 2 {
			sum += uint32(binary.BigEndian.Uint16(srcIP[i : i+2]))
			sum += uint32(binary.BigEndian.Uint16(dstIP[i : i+2]))
		}
		sum += uint32(len(udpSegment))
		sum += uint32(17) // Next header: UDP
	}

	// UDP header and data
	for i := 0; i < len(udpSegment); i += 2 {
		if i == 6 { // Skip checksum field itself
			continue
		}
		if i+1 < len(udpSegment) {
			sum += uint32(binary.BigEndian.Uint16(udpSegment[i : i+2]))
		} else {
			// Odd length, pad with zero
			sum += uint32(udpSegment[i]) << 8
		}
	}

	// Add carry
	for sum > 0xffff {
		sum = (sum & 0xffff) + (sum >> 16)
	}
	checksum := ^uint16(sum)
	if checksum == 0 {
		return 0xffff // UDP uses 0xffff for zero checksum
	}
	return checksum
}
