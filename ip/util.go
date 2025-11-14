package ip

import (
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
