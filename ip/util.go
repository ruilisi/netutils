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
