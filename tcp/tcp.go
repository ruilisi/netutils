package tcp

import (
	"encoding/binary"
	"fmt"
	"net"
)

/*
SummarizeIPv4Packet parses a raw IPv4 packet and returns a human readable summary.

Supported L4 protocols:
- TCP (protocol = 6)
- ICMPv4 (protocol = 1)

For other L4 protocols a short notice is returned.

The summary always includes:
- Source / destination IPv4 addresses
- IPv4 total length (possibly truncated if capture shorter than header's total length)
- Parsed protocol specific details
- Payload size in bytes (Payload=..B)
*/
func SummarizeIPv4Packet(pkt []byte) string {
	if len(pkt) < 20 {
		return "invalid IPv4 packet (too short)"
	}

	// ---- IPv4 Header ----
	version := pkt[0] >> 4
	if version != 4 {
		return "not IPv4"
	}

	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl {
		return "invalid IPv4 header length"
	}

	totalLenField := int(binary.BigEndian.Uint16(pkt[2:4]))
	totalLen := totalLenField
	if totalLen > len(pkt) { // truncated capture safeguard
		totalLen = len(pkt)
	}
	proto := pkt[9]
	srcIP := net.IP(pkt[12:16])
	dstIP := net.IP(pkt[16:20])

	ipPrefix := fmt.Sprintf("IPv4 %s -> %s | Len=%d", srcIP, dstIP, totalLenField)

	switch proto {
	case 6: // TCP
		return summarizeTCP(pkt, ihl, totalLen, ipPrefix)
	case 1: // ICMPv4
		return summarizeICMPv4(pkt, ihl, totalLen, ipPrefix)
	default:
		return fmt.Sprintf("%s | Proto=%d (unsupported) | Payload=%dB", ipPrefix, proto, max(totalLen-ihl, 0))
	}
}

// summarizeTCP handles TCP specific parsing and summary formatting.
func summarizeTCP(pkt []byte, ihl, totalLen int, ipPrefix string) string {
	if len(pkt) < ihl+20 {
		return ipPrefix + " | TCP (invalid header)"
	}

	tcp := pkt[ihl:]
	if len(tcp) < 20 {
		return ipPrefix + " | TCP (len < 20)"
	}

	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	seq := binary.BigEndian.Uint32(tcp[4:8])
	ack := binary.BigEndian.Uint32(tcp[8:12])
	dataOffset := int((tcp[12] >> 4) * 4)
	if dataOffset < 20 || len(tcp) < dataOffset {
		return ipPrefix + " | TCP (invalid data offset)"
	}
	flags := tcp[13]
	window := binary.BigEndian.Uint16(tcp[14:16])

	// Flags
	fsyn := (flags & 0x02) != 0
	fack := (flags & 0x10) != 0
	ffin := (flags & 0x01) != 0
	frst := (flags & 0x04) != 0
	fpsh := (flags & 0x08) != 0
	furg := (flags & 0x20) != 0
	fece := (flags & 0x40) != 0
	fcwr := (flags & 0x80) != 0

	// Simple handshake phase detection (heuristic)
	hs := ""
	switch {
	case fsyn && !fack && !ffin && !frst:
		hs = "Handshake #1 (SYN)"
	case fsyn && fack && !ffin && !frst:
		hs = "Handshake #2 (SYN+ACK)"
	case !fsyn && fack && !ffin && !frst:
		hs = "Handshake ACK"
	}

	payloadLen := totalLen - ihl - dataOffset
	if payloadLen < 0 {
		payloadLen = 0
	}

	return fmt.Sprintf(
		"%s | Proto=6 TCP %d->%d | Seq=%d Ack=%d | Win=%d | HdrLen=%d | Payload=%dB | Flags=[CWR=%v,ECE=%v,URG=%v,ACK=%v,PSH=%v,RST=%v,SYN=%v,FIN=%v] %s",
		ipPrefix, srcPort, dstPort, seq, ack, window, dataOffset, payloadLen,
		fcwr, fece, furg, fack, fpsh, frst, fsyn, ffin, hs,
	)
}

// summarizeICMPv4 handles ICMPv4 parsing and summary formatting.
func summarizeICMPv4(pkt []byte, ihl, totalLen int, ipPrefix string) string {
	if len(pkt) < ihl+4 {
		return ipPrefix + " | ICMP (too short)"
	}
	icmp := pkt[ihl:]
	icmpLen := totalLen - ihl
	if icmpLen < 4 {
		return ipPrefix + " | ICMP (len < 4)"
	}

	icmpType := icmp[0]
	icmpCode := icmp[1]
	checksum := binary.BigEndian.Uint16(icmp[2:4])
	desc := icmpTypeString(icmpType, icmpCode)

	extra := ""
	// Echo Request (8) / Echo Reply (0)
	if (icmpType == 8 || icmpType == 0) && icmpLen >= 8 {
		id := binary.BigEndian.Uint16(icmp[4:6])
		seq := binary.BigEndian.Uint16(icmp[6:8])
		payloadLen := icmpLen - 8
		extra = fmt.Sprintf(" | Echo id=%d seq=%d Payload=%dB", id, seq, max(payloadLen, 0))
	} else if (icmpType == 3 || icmpType == 11 || icmpType == 5 || icmpType == 4) && icmpLen >= 8 {
		// Common control messages show the 32-bit field and remaining payload
		raw := binary.BigEndian.Uint32(icmp[4:8])
		payloadLen := icmpLen - 8
		extra = fmt.Sprintf(" | Data=0x%08x Payload=%dB", raw, max(payloadLen, 0))
	} else if icmpLen > 4 {
		payloadLen := icmpLen - 4
		extra = fmt.Sprintf(" | Payload=%dB", max(payloadLen, 0))
	}

	return fmt.Sprintf("%s | Proto=1 ICMP Type=%d Code=%d (%s) Checksum=0x%04x%s", ipPrefix, icmpType, icmpCode, desc, checksum, extra)
}

// icmpTypeString returns a human readable string for ICMP type/code combinations.
func icmpTypeString(t, code byte) string {
	switch t {
	case 0:
		return "Echo Reply"
	case 3:
		switch code {
		case 0:
			return "Dest Unreachable (Net)"
		case 1:
			return "Dest Unreachable (Host)"
		case 2:
			return "Dest Unreachable (Protocol)"
		case 3:
			return "Dest Unreachable (Port)"
		case 4:
			return "Dest Unreachable (Fragmentation Needed)"
		case 5:
			return "Dest Unreachable (Source Route Failed)"
		case 6:
			return "Dest Unreachable (Net Unknown)"
		case 7:
			return "Dest Unreachable (Host Unknown)"
		case 8:
			return "Dest Unreachable (Src Host Isolated)"
		case 9:
			return "Dest Unreachable (Net Prohibited)"
		case 10:
			return "Dest Unreachable (Host Prohibited)"
		case 11:
			return "Dest Unreachable (TOS Net)"
		case 12:
			return "Dest Unreachable (TOS Host)"
		case 13:
			return "Dest Unreachable (Admin Prohibited)"
		case 14:
			return "Dest Unreachable (Host Precedence Violation)"
		case 15:
			return "Dest Unreachable (Precedence Cutoff)"
		default:
			return "Dest Unreachable (Other)"
		}
	case 4:
		return "Source Quench (Deprecated)"
	case 5:
		switch code {
		case 0:
			return "Redirect (Net)"
		case 1:
			return "Redirect (Host)"
		case 2:
			return "Redirect (TOS+Net)"
		case 3:
			return "Redirect (TOS+Host)"
		default:
			return "Redirect"
		}
	case 8:
		return "Echo Request"
	case 9:
		return "Router Advertisement"
	case 10:
		return "Router Solicitation"
	case 11:
		if code == 0 {
			return "Time Exceeded (TTL)"
		} else if code == 1 {
			return "Time Exceeded (Frag Reassembly)"
		}
		return "Time Exceeded"
	case 12:
		if code == 0 {
			return "Parameter Prob (Pointer)"
		} else if code == 1 {
			return "Parameter Prob (Missing Option)"
		} else if code == 2 {
			return "Parameter Prob (Bad Length)"
		}
		return "Parameter Problem"
	case 13:
		return "Timestamp Request"
	case 14:
		return "Timestamp Reply"
	case 15:
		return "Info Request (Obsolete)"
	case 16:
		return "Info Reply (Obsolete)"
	case 17:
		return "Address Mask Request"
	case 18:
		return "Address Mask Reply"
	default:
		return "Unknown/Experimental"
	}
}

// max returns the larger of a or b.
func max(a, b int) int {
	if a > b {
		return a
	}
	return b
}
