package tcp

import (
	"encoding/binary"
	"fmt"
	"net"
)

// ExtractIPTCPSummary parses an IPv4+TCP packet and returns a summary string
func ExtractIPTCPSummary(pkt []byte) string {
	if len(pkt) < 20 {
		return "invalid IPv4 packet (too short)"
	}

	// ---- IPv4 Header ----
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+20 {
		return "invalid IPv4 header length"
	}

	totalLen := int(binary.BigEndian.Uint16(pkt[2:4]))
	proto := pkt[9]
	srcIP := net.IP(pkt[12:16])
	dstIP := net.IP(pkt[16:20])

	if proto != 6 { // TCP protocol number = 6
		return fmt.Sprintf("Not TCP (proto=%d) %s -> %s", proto, srcIP, dstIP)
	}

	// ---- TCP Header ----
	tcp := pkt[ihl:]
	srcPort := binary.BigEndian.Uint16(tcp[0:2])
	dstPort := binary.BigEndian.Uint16(tcp[2:4])
	seq := binary.BigEndian.Uint32(tcp[4:8])
	ack := binary.BigEndian.Uint32(tcp[8:12])
	dataOffset := (tcp[12] >> 4) * 4
	flags := tcp[13]
	window := binary.BigEndian.Uint16(tcp[14:16])

	// Flags
	fsyn := (flags & 0x02) != 0
	fack := (flags & 0x10) != 0
	ffin := (flags & 0x01) != 0
	frst := (flags & 0x04) != 0

	// Handshake phase detection
	hs := ""
	switch {
	case fsyn && !fack:
		hs = "Handshake #1 (SYN)"
	case fsyn && fack:
		hs = "Handshake #2 (SYN+ACK)"
	case !fsyn && fack:
		hs = "Handshake #3 (ACK)"
	}

	// Payload length
	payloadLen := totalLen - ihl - int(dataOffset)
	if payloadLen < 0 {
		payloadLen = 0
	}

	return fmt.Sprintf(
		"IPv4 %s -> %s | TCP %d -> %d | Seq=%d Ack=%d | Win=%d | HdrLen=%d | Payload=%d | Flags=[SYN=%v,ACK=%v,FIN=%v,RST=%v] %s",
		srcIP, dstIP,
		srcPort, dstPort, seq, ack, window, dataOffset, payloadLen,
		fsyn, fack, ffin, frst, hs,
	)
}
