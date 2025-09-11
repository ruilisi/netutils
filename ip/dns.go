package ip

import (
	"encoding/binary"
	"net"
	"strings"
)

// ExtractDNSFromPacket inspects a raw IP packet, auto-detects IPv4/IPv6,
// finds a UDP/53 payload, and parses the DNS message to return:
// - dnsPayload: raw DNS bytes starting at the DNS header
// - qnames: question names (from QD section)
// - ips: resolved IPs (A/AAAA) from the Answer section (responses only)
// - isQuery: true if QR=0 (query), false if QR=1 (response)
// - ok: true if this looks like a valid DNS packet
func ExtractDNSFromPacket(pkt []byte) (dnsPayload []byte, qnames []string, ips []net.IP, isQuery bool, ok bool) {
	if len(pkt) < 1 {
		return nil, nil, nil, false, false
	}
	switch pkt[0] >> 4 {
	case 4:
		return extractDNSFromIPv4(pkt)
	case 6:
		return extractDNSFromIPv6(pkt)
	default:
		return nil, nil, nil, false, false
	}
}

func extractDNSFromIPv4(pkt []byte) (dnsPayload []byte, qnames []string, ips []net.IP, isQuery bool, ok bool) {
	if len(pkt) < 20 {
		return nil, nil, nil, false, false
	}
	ihl := int(pkt[0]&0x0F) * 4
	if ihl < 20 || len(pkt) < ihl+8 {
		return nil, nil, nil, false, false
	}
	// Fragmentation guard: skip non-first fragments or more fragments.
	frag := binary.BigEndian.Uint16(pkt[6:8])
	mf := (frag & 0x2000) != 0
	off := (frag & 0x1FFF)
	if mf || off != 0 {
		return nil, nil, nil, false, false
	}
	if pkt[9] != 17 { // UDP
		return nil, nil, nil, false, false
	}
	udp := pkt[ihl:]
	if len(udp) < 8 {
		return nil, nil, nil, false, false
	}
	srcPort := binary.BigEndian.Uint16(udp[0:2])
	dstPort := binary.BigEndian.Uint16(udp[2:4])
	if srcPort != 53 && dstPort != 53 {
		return nil, nil, nil, false, false
	}
	udpLen := int(binary.BigEndian.Uint16(udp[4:6]))
	payloadOffset := ihl + 8
	payloadEnd := payloadOffset + (udpLen - 8)
	if payloadEnd > len(pkt) {
		payloadEnd = len(pkt)
	}
	if payloadOffset >= payloadEnd || payloadOffset > len(pkt) {
		return nil, nil, nil, false, false
	}
	payload := pkt[payloadOffset:payloadEnd]
	qn, ipList, query, ok2 := parseDNSMessage(payload)
	if !ok2 {
		return nil, nil, nil, false, false
	}
	return payload, qn, ipList, query, true
}

func extractDNSFromIPv6(pkt []byte) (dnsPayload []byte, qnames []string, ips []net.IP, isQuery bool, ok bool) {
	if len(pkt) < 40 {
		return nil, nil, nil, false, false
	}
	next := pkt[6]
	payloadLen := int(binary.BigEndian.Uint16(pkt[4:6])) // bytes after fixed 40-byte header
	i := 40
	remaining := payloadLen

	// Walk common IPv6 extension headers to find UDP.
	for {
		if next == 17 { // UDP
			break
		}
		if remaining <= 0 || i >= len(pkt) {
			return nil, nil, nil, false, false
		}
		switch next {
		case 0, 43, 60: // Hop-by-Hop, Routing, Dest Options
			if i+2 > len(pkt) {
				return nil, nil, nil, false, false
			}
			n := pkt[i]        // Next Header
			extLen := pkt[i+1] // in 8-octet units, not including first 8 bytes
			size := int(extLen+1) * 8
			if i+size > len(pkt) || size > remaining {
				return nil, nil, nil, false, false
			}
			next = n
			i += size
			remaining -= size
		case 44: // Fragment
			// 8 bytes fixed: NextHeader(1), Reserved(1), FragOff/Flags(2), ID(4)
			if i+8 > len(pkt) || remaining < 8 {
				return nil, nil, nil, false, false
			}
			n := pkt[i]
			fragOffFlags := binary.BigEndian.Uint16(pkt[i+2 : i+4])
			fragOffset := fragOffFlags & 0xFFF8
			mFlag := (fragOffFlags & 0x0001) != 0
			// Only attempt to parse first fragment with offset 0. If more fragments, skip.
			if fragOffset != 0 || mFlag {
				return nil, nil, nil, false, false
			}
			next = n
			i += 8
			remaining -= 8
		case 51: // AH (Authentication Header) - length in 4-octet units, including first 2 words
			if i+2 > len(pkt) || remaining < 2 {
				return nil, nil, nil, false, false
			}
			n := pkt[i]
			len4 := int(pkt[i+1]+2) * 4
			if i+len4 > len(pkt) || len4 > remaining {
				return nil, nil, nil, false, false
			}
			next = n
			i += len4
			remaining -= len4
		case 50: // ESP - cannot parse further without SA; bail
			return nil, nil, nil, false, false
		default:
			// Unknown header; bail
			return nil, nil, nil, false, false
		}
	}

	// At UDP header
	if i+8 > len(pkt) || remaining < 8 {
		return nil, nil, nil, false, false
	}
	srcPort := binary.BigEndian.Uint16(pkt[i : i+2])
	dstPort := binary.BigEndian.Uint16(pkt[i+2 : i+4])
	if srcPort != 53 && dstPort != 53 {
		return nil, nil, nil, false, false
	}
	udpLen := int(binary.BigEndian.Uint16(pkt[i+4 : i+6]))
	payloadOffset := i + 8
	payloadEnd := payloadOffset + (udpLen - 8)
	if payloadEnd > len(pkt) {
		payloadEnd = len(pkt)
	}
	if payloadOffset >= payloadEnd || payloadOffset > len(pkt) {
		return nil, nil, nil, false, false
	}
	payload := pkt[payloadOffset:payloadEnd]
	qn, ipList, query, ok2 := parseDNSMessage(payload)
	if !ok2 {
		return nil, nil, nil, false, false
	}
	return payload, qn, ipList, query, true
}

// parseDNSMessage parses DNS payload, returning question names and A/AAAA IPs.
func parseDNSMessage(payload []byte) (qnames []string, ips []net.IP, isQuery bool, ok bool) {
	if len(payload) < 12 {
		return nil, nil, false, false
	}
	flags := binary.BigEndian.Uint16(payload[2:4])
	qdCount := int(binary.BigEndian.Uint16(payload[4:6]))
	anCount := int(binary.BigEndian.Uint16(payload[6:8]))
	isQuery = (flags & 0x8000) == 0 // QR=0

	off := 12
	qnames = make([]string, 0, qdCount)
	for i := 0; i < qdCount; i++ {
		name, newOff, okName := readDNSName(payload, off, 0)
		if !okName {
			return nil, nil, false, false
		}
		off = newOff
		if off+4 > len(payload) {
			return nil, nil, false, false
		}
		off += 4 // QTYPE+QCLASS
		qnames = append(qnames, name)
	}

	if isQuery || anCount == 0 {
		return qnames, nil, isQuery, true
	}

	ipList := make([]net.IP, 0, anCount)
	for i := 0; i < anCount; i++ {
		_, newOff, okName := readDNSName(payload, off, 0)
		if !okName {
			return nil, nil, false, false
		}
		off = newOff
		if off+10 > len(payload) {
			return nil, nil, false, false
		}
		typ := binary.BigEndian.Uint16(payload[off : off+2])
		rdlen := int(binary.BigEndian.Uint16(payload[off+8 : off+10]))
		off += 10
		if off+rdlen > len(payload) {
			return nil, nil, false, false
		}
		rdata := payload[off : off+rdlen]
		off += rdlen

		switch typ {
		case 1: // A
			if len(rdata) == 4 {
				ipList = append(ipList, net.IPv4(rdata[0], rdata[1], rdata[2], rdata[3]))
			}
		case 28: // AAAA
			if len(rdata) == 16 {
				ipList = append(ipList, net.IP(rdata[:16]))
			}
		}
	}
	return qnames, ipList, isQuery, true
}

// readDNSName reads a (possibly compressed) DNS name starting at off.
// Returns the name, the offset immediately after where the name appears in the stream,
// and ok. Depth limits prevent pointer loops.
func readDNSName(msg []byte, off int, depth int) (string, int, bool) {
	if depth > 10 {
		return "", 0, false
	}
	var labels []string
	jumped := false
	ptrEnd := -1

	for {
		if off >= len(msg) {
			return "", 0, false
		}
		l := int(msg[off])
		off++
		if l == 0 {
			break
		}
		switch l & 0xC0 {
		case 0x00:
			if off+l > len(msg) {
				return "", 0, false
			}
			labels = append(labels, string(msg[off:off+l]))
			off += l
		case 0xC0:
			if off >= len(msg) {
				return "", 0, false
			}
			if !jumped {
				ptrEnd = off + 1
			}
			ptr := ((l & 0x3F) << 8) | int(msg[off])
			off++
			jumped = true
			name, _, ok := readDNSName(msg, ptr, depth+1)
			if !ok {
				return "", 0, false
			}
			if len(labels) > 0 && name != "" {
				name = strings.Join(labels, ".") + "." + name
			} else if len(labels) > 0 {
				name = strings.Join(labels, ".")
			}
			if ptrEnd != -1 {
				return name, ptrEnd, true
			}
			return name, off, true
		default:
			return "", 0, false
		}
	}
	name := strings.Join(labels, ".")
	if jumped && ptrEnd != -1 {
		return name, ptrEnd, true
	}
	return name, off, true
}
