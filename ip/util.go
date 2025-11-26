package ip

import (
	"encoding/binary"
	"net"
	"strconv"
)

func IsRealIPPort(s string) bool {
	host, portStr, err := net.SplitHostPort(s)
	if err != nil {
		return false
	}

	// Check port
	port, err := strconv.Atoi(portStr)
	if err != nil || port < 1 || port > 65535 {
		return false
	}

	// Check host is a valid IP (IPv4 or IPv6)
	if net.ParseIP(host) == nil {
		return false
	}

	return true
}

// isIPv6 checks if an IP address is IPv6
func IsIPv6(ip net.IP) bool {
	return ip.To4() == nil && len(ip) == net.IPv6len
}

// IpToUint32 converts an IPv4 address to uint32 (network byte order)
func IpToUint32(ip net.IP) uint32 {
	ip = ip.To4()
	if ip == nil {
		return 0
	}
	return binary.BigEndian.Uint32(ip)
}

// GetPorts extracts source and destination ports from an IP packet.
// Returns (srcPort, dstPort) for TCP/UDP packets, or (0, 0) for other protocols
// or malformed packets.
func GetPorts(packet []byte) (srcPort, dstPort uint16) {
	if len(packet) < 20 {
		return 0, 0
	}

	// Determine IP version and header length
	version := packet[0] >> 4
	var headerLen int
	var protocol byte

	switch version {
	case 4: // IPv4
		headerLen = int(packet[0]&0x0F) * 4
		if len(packet) < headerLen || headerLen < 20 {
			return 0, 0
		}
		protocol = packet[9]
	case 6: // IPv6
		headerLen = 40 // IPv6 has fixed 40-byte header
		if len(packet) < headerLen {
			return 0, 0
		}
		protocol = packet[6]
	default:
		return 0, 0
	}

	// Check if we have enough data for transport layer header
	if len(packet) < headerLen+4 {
		return 0, 0
	}

	// Protocol numbers: TCP = 6, UDP = 17
	// Both TCP and UDP have ports at the same offset (first 4 bytes)
	if protocol == 6 || protocol == 17 {
		transportHeader := packet[headerLen:]
		srcPort = binary.BigEndian.Uint16(transportHeader[0:2])
		dstPort = binary.BigEndian.Uint16(transportHeader[2:4])
	}

	return srcPort, dstPort
}
