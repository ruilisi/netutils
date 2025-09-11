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
		return "IPv6 packet"
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
