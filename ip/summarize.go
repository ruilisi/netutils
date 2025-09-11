package ip

import (
	"encoding/binary"
	"fmt"
	"net"
	"strings"
)

/*
SummarizePacket parses a raw IPv4 packet and returns a human readable summary.

Supported L4 protocols:
- TCP (protocol = 6)
- ICMPv4 (protocol = 1)
- UDP (protocol = 17)

For other L4 protocols a short notice is returned.

The summary always includes:
- Source / destination IPv4 addresses
- IPv4 total length (possibly truncated if capture shorter than header's total length)
- Parsed protocol specific details
- Payload size in bytes (Payload=..B)
*/

func SummarizePacket(pkt []byte) string {
	if len(pkt) < 1 {
		return "invalid packet (too short)"
	}

	version := pkt[0] >> 4
	switch version {
	case 4:
		return summarizeIPv4(pkt)
	case 6:
		return summarizeIPv6(pkt)
	default:
		return fmt.Sprintf("Unknown protocol version: %d", version)
	}
}

func summarizeIPv4(pkt []byte) string {
	if len(pkt) < 20 {
		return "invalid IPv4 packet (too short)"
	}

	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return "invalid IPv4 header length"
	}

	totalLenField := int(binary.BigEndian.Uint16(pkt[2:4]))
	totalLen := totalLenField
	if totalLen > len(pkt) {
		totalLen = len(pkt)
	}
	proto := pkt[9]
	srcIP := net.IP(pkt[12:16])
	dstIP := net.IP(pkt[16:20])

	switch proto {
	case 6: // TCP
		return summarizeTCPShort(pkt, ihl, totalLen, srcIP, dstIP)
	case 1: // ICMPv4
		return summarizeICMPv4Short(pkt, ihl, totalLen, srcIP, dstIP)
	case 17: // UDP
		return summarizeUDPShort(pkt, ihl, totalLen, srcIP, dstIP)
	default:
		return fmt.Sprintf("IPv4 %s→%s | Proto=%d | Payload=%dB", srcIP, dstIP, proto, max(totalLen-ihl, 0))
	}
}

// summarizeTCPShort outputs a minimal TCP summary, with handshake as emoji if detected
func summarizeTCPShort(pkt []byte, ihl, totalLen int, srcIP, dstIP net.IP) string {
	if len(pkt) < ihl+20 {
		return fmt.Sprintf("IPv4 %s→%s TCP | invalid header", srcIP, dstIP)
	}

	tcp := pkt[ihl:]
	if len(tcp) < 20 {
		return fmt.Sprintf("IPv4 %s→%s TCP | len < 20", srcIP, dstIP)
	}

	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	seq := binary.BigEndian.Uint32(tcp[4:8])
	ack := binary.BigEndian.Uint32(tcp[8:12])
	dataOffset := int((tcp[12] >> 4) * 4)
	if dataOffset < 20 || len(tcp) < dataOffset {
		return fmt.Sprintf("IPv4 %s→%s TCP | invalid data offset", srcIP, dstIP)
	}
	flags := tcp[13]
	payloadLen := max(totalLen-ihl-dataOffset, 0)

	// Distinct emoji for handshake phase
	handshake := ""
	switch {
	case (flags&0x02) != 0 && (flags&0x10) == 0 && (flags&0x01) == 0 && (flags&0x04) == 0:
		handshake = "👋" // SYN
	case (flags&0x02) != 0 && (flags&0x10) != 0 && (flags&0x01) == 0 && (flags&0x04) == 0:
		handshake = "🤝" // SYN+ACK
	case (flags&0x02) == 0 && (flags&0x10) != 0 && (flags&0x01) == 0 && (flags&0x04) == 0:
		handshake = "👍" // ACK
	}

	// Show only essential flags: SYN, ACK, FIN, RST
	flagStr := ""
	if (flags & 0x02) != 0 {
		flagStr += "SYN "
	}
	if (flags & 0x10) != 0 {
		flagStr += "ACK "
	}
	if (flags & 0x01) != 0 {
		flagStr += "FIN "
	}
	if (flags & 0x04) != 0 {
		flagStr += "RST "
	}
	flagStr = strings.TrimSpace(flagStr)

	// Output summary
	if handshake != "" && flagStr != "" {
		// If handshake, show only emoji, not flags
		return fmt.Sprintf("IPv4 %s:%d→%s:%d TCP %s | Seq=%d Ack=%d | %dB", srcIP, srcPort, dstIP, dstPort, handshake, seq, ack, payloadLen)
	}
	return fmt.Sprintf("IPv4 %s:%d→%s:%d TCP %s | Seq=%d Ack=%d | %dB", srcIP, srcPort, dstIP, dstPort, flagStr, seq, ack, payloadLen)
}

func summarizeICMPv4Short(pkt []byte, ihl, totalLen int, srcIP, dstIP net.IP) string {
	if len(pkt) < ihl+4 {
		return fmt.Sprintf("IPv4 %s→%s ICMP | too short", srcIP, dstIP)
	}
	icmp := pkt[ihl:]
	icmpLen := totalLen - ihl
	if icmpLen < 4 {
		return fmt.Sprintf("IPv4 %s→%s ICMP | len < 4", srcIP, dstIP)
	}

	icmpType := icmp[0]
	icmpCode := icmp[1]
	payloadLen := max(icmpLen-4, 0)

	desc := icmpTypeStringShort(icmpType, icmpCode)

	return fmt.Sprintf("IPv4 %s→%s ICMP %s | %dB", srcIP, dstIP, desc, payloadLen)
}

// summarizeUDPShort outputs a minimal UDP summary
func summarizeUDPShort(pkt []byte, ihl, totalLen int, srcIP, dstIP net.IP) string {
	if len(pkt) < ihl+8 {
		return fmt.Sprintf("IPv4 %s→%s UDP | invalid header", srcIP, dstIP)
	}
	udp := pkt[ihl:]
	if len(udp) < 8 {
		return fmt.Sprintf("IPv4 %s→%s UDP | len < 8", srcIP, dstIP)
	}

	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	payloadLen := max(udpLen-8, 0)
	// If udpLen > totalLen-ihl, adjust to actual captured
	if udpLen > totalLen-ihl {
		payloadLen = max(totalLen-ihl-8, 0)
	}

	return fmt.Sprintf("IPv4 %s:%d→%s:%d UDP | %dB", srcIP, srcPort, dstIP, dstPort, payloadLen)
}

// Short human readable string for ICMP type/code
func icmpTypeStringShort(t, code byte) string {
	switch t {
	case 0:
		return "Echo Reply"
	case 3:
		return "Unreach"
	case 8:
		return "Echo Req"
	case 11:
		return "Time Exceeded"
	default:
		return fmt.Sprintf("Type=%d", t)
	}
}

// max returns the larger of a or b.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}

func summarizeIPv6(pkt []byte) string {
	if len(pkt) < 40 {
		return "invalid IPv6 packet (too short)"
	}

	// IPv6 header fields
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6]))
	nextHeader := pkt[6]
	srcIP := net.IP(pkt[8:24])
	dstIP := net.IP(pkt[24:40])

	// Calculate total length
	headerLen := 40
	totalLenField := headerLen + payloadLen
	totalLen := totalLenField
	if totalLen > len(pkt) {
		totalLen = len(pkt)
	}

	// Parse extension headers to find the actual L4 protocol and offset
	l4Proto, l4Offset, err := parseIPv6ExtHeaders(pkt, nextHeader, 40)
	if err != nil {
		return fmt.Sprintf("IPv6 %s→%s | %s", srcIP, dstIP, err.Error())
	}

	switch l4Proto {
	case 6: // TCP
		return summarizeTCPShortIPv6(pkt, l4Offset, totalLen, srcIP, dstIP)
	case 17: // UDP
		return summarizeUDPShortIPv6(pkt, l4Offset, totalLen, srcIP, dstIP)
	case 58: // ICMPv6
		return summarizeICMPv6Short(pkt, l4Offset, totalLen, srcIP, dstIP)
	default:
		payloadSize := max(totalLen-l4Offset, 0)
		return fmt.Sprintf("IPv6 %s→%s | Proto=%d | %dB", srcIP, dstIP, l4Proto, payloadSize)
	}
}

// parseIPv6ExtHeaders parses IPv6 extension headers and returns the final L4 protocol and offset
func parseIPv6ExtHeaders(pkt []byte, nextHeader byte, offset int) (byte, int, error) {
	currentHeader := nextHeader
	currentOffset := offset

	// Iterate through extension headers
	for {
		switch currentHeader {
		case 0: // Hop-by-Hop Options
			if currentOffset+2 > len(pkt) {
				return 0, 0, fmt.Errorf("invalid/short Hop-by-Hop header")
			}
			extLen := (int(pkt[currentOffset+1]) + 1) * 8
			if currentOffset+extLen > len(pkt) {
				return 0, 0, fmt.Errorf("invalid/short Hop-by-Hop header")
			}
			currentHeader = pkt[currentOffset]
			currentOffset += extLen

		case 43: // Routing
			if currentOffset+2 > len(pkt) {
				return 0, 0, fmt.Errorf("invalid/short Routing header")
			}
			extLen := (int(pkt[currentOffset+1]) + 1) * 8
			if currentOffset+extLen > len(pkt) {
				return 0, 0, fmt.Errorf("invalid/short Routing header")
			}
			currentHeader = pkt[currentOffset]
			currentOffset += extLen

		case 44: // Fragment
			if currentOffset+8 > len(pkt) {
				return 0, 0, fmt.Errorf("invalid/short Fragment header")
			}
			currentHeader = pkt[currentOffset]
			currentOffset += 8

		case 60: // Destination Options
			if currentOffset+2 > len(pkt) {
				return 0, 0, fmt.Errorf("invalid/short Destination Options header")
			}
			extLen := (int(pkt[currentOffset+1]) + 1) * 8
			if currentOffset+extLen > len(pkt) {
				return 0, 0, fmt.Errorf("invalid/short Destination Options header")
			}
			currentHeader = pkt[currentOffset]
			currentOffset += extLen

		case 51: // Authentication Header
			if currentOffset+2 > len(pkt) {
				return 0, 0, fmt.Errorf("invalid/short Authentication header")
			}
			extLen := (int(pkt[currentOffset+1]) + 2) * 4
			if currentOffset+extLen > len(pkt) {
				return 0, 0, fmt.Errorf("invalid/short Authentication header")
			}
			currentHeader = pkt[currentOffset]
			currentOffset += extLen

		default:
			// Not an extension header, this is the final L4 protocol
			return currentHeader, currentOffset, nil
		}
	}
}

// summarizeTCPShortIPv6 adapts the IPv4 TCP summarization for IPv6
func summarizeTCPShortIPv6(pkt []byte, l4Offset, totalLen int, srcIP, dstIP net.IP) string {
	if len(pkt) < l4Offset+20 {
		return fmt.Sprintf("IPv6 %s→%s TCP | invalid header", srcIP, dstIP)
	}

	tcp := pkt[l4Offset:]
	if len(tcp) < 20 {
		return fmt.Sprintf("IPv6 %s→%s TCP | len < 20", srcIP, dstIP)
	}

	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	seq := binary.BigEndian.Uint32(tcp[4:8])
	ack := binary.BigEndian.Uint32(tcp[8:12])
	dataOffset := int((tcp[12] >> 4) * 4)
	if dataOffset < 20 || len(tcp) < dataOffset {
		return fmt.Sprintf("IPv6 %s→%s TCP | invalid data offset", srcIP, dstIP)
	}
	flags := tcp[13]
	payloadLen := max(totalLen-l4Offset-dataOffset, 0)

	// Distinct emoji for handshake phase
	handshake := ""
	switch {
	case (flags&0x02) != 0 && (flags&0x10) == 0 && (flags&0x01) == 0 && (flags&0x04) == 0:
		handshake = "👋" // SYN
	case (flags&0x02) != 0 && (flags&0x10) != 0 && (flags&0x01) == 0 && (flags&0x04) == 0:
		handshake = "🤝" // SYN+ACK
	case (flags&0x02) == 0 && (flags&0x10) != 0 && (flags&0x01) == 0 && (flags&0x04) == 0:
		handshake = "👍" // ACK
	}

	// Show only essential flags: SYN, ACK, FIN, RST
	flagStr := ""
	if (flags & 0x02) != 0 {
		flagStr += "SYN "
	}
	if (flags & 0x10) != 0 {
		flagStr += "ACK "
	}
	if (flags & 0x01) != 0 {
		flagStr += "FIN "
	}
	if (flags & 0x04) != 0 {
		flagStr += "RST "
	}
	flagStr = strings.TrimSpace(flagStr)

	// Output summary
	if handshake != "" && flagStr != "" {
		// If handshake, show only emoji, not flags
		return fmt.Sprintf("IPv6 %s:%d→%s:%d TCP %s | Seq=%d Ack=%d | %dB", srcIP, srcPort, dstIP, dstPort, handshake, seq, ack, payloadLen)
	}
	return fmt.Sprintf("IPv6 %s:%d→%s:%d TCP %s | Seq=%d Ack=%d | %dB", srcIP, srcPort, dstIP, dstPort, flagStr, seq, ack, payloadLen)
}

// summarizeUDPShortIPv6 adapts the IPv4 UDP summarization for IPv6
func summarizeUDPShortIPv6(pkt []byte, l4Offset, totalLen int, srcIP, dstIP net.IP) string {
	if len(pkt) < l4Offset+8 {
		return fmt.Sprintf("IPv6 %s→%s UDP | invalid header", srcIP, dstIP)
	}
	udp := pkt[l4Offset:]
	if len(udp) < 8 {
		return fmt.Sprintf("IPv6 %s→%s UDP | len < 8", srcIP, dstIP)
	}

	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	payloadLen := max(udpLen-8, 0)
	// If udpLen > totalLen-l4Offset, adjust to actual captured
	if udpLen > totalLen-l4Offset {
		payloadLen = max(totalLen-l4Offset-8, 0)
	}

	return fmt.Sprintf("IPv6 %s:%d→%s:%d UDP | %dB", srcIP, srcPort, dstIP, dstPort, payloadLen)
}

// summarizeICMPv6Short outputs a minimal ICMPv6 summary
func summarizeICMPv6Short(pkt []byte, l4Offset, totalLen int, srcIP, dstIP net.IP) string {
	if len(pkt) < l4Offset+4 {
		return fmt.Sprintf("IPv6 %s→%s ICMPv6 | too short", srcIP, dstIP)
	}
	icmp := pkt[l4Offset:]
	icmpLen := totalLen - l4Offset
	if icmpLen < 4 {
		return fmt.Sprintf("IPv6 %s→%s ICMPv6 | len < 4", srcIP, dstIP)
	}

	icmpType := icmp[0]
	icmpCode := icmp[1]
	payloadLen := max(icmpLen-4, 0)

	desc := icmpv6TypeStringShort(icmpType, icmpCode)

	return fmt.Sprintf("IPv6 %s→%s ICMPv6 %s | %dB", srcIP, dstIP, desc, payloadLen)
}

// icmpv6TypeStringShort returns short human readable string for ICMPv6 type/code
func icmpv6TypeStringShort(t, code byte) string {
	switch t {
	case 1:
		return "Unreach"
	case 2:
		return "Packet Too Big"
	case 3:
		return "Time Exceeded"
	case 4:
		return "Parameter Problem"
	case 128:
		return "Echo Req"
	case 129:
		return "Echo Reply"
	case 133:
		return "Router Solicitation"
	case 134:
		return "Router Advertisement"
	case 135:
		return "Neighbor Solicitation"
	case 136:
		return "Neighbor Advertisement"
	default:
		return fmt.Sprintf("Type=%d", t)
	}
}
