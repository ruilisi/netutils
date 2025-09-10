package ip

import (
	"bytes"
	"net"
	"strings"
)

// StrToIPNets convert routes of string with delimiter to slice of *net.IPNet
func StrToIPNets(routes string, delimiter string) []*net.IPNet {
	var ipNets []*net.IPNet
	routeList := strings.Split(routes, delimiter)
	for _, route := range routeList {
		_, ipNet, err := net.ParseCIDR(strings.TrimSpace(route))
		if err == nil {
			ipNets = append(ipNets, ipNet)
		}
	}
	return ipNets
}

// BytesToIPNets parses IP networks from a []byte separated by sep
func BytesToIPNets(data []byte, sep []byte) []*net.IPNet {
	parts := bytes.Split(data, sep)
	var nets []*net.IPNet
	for _, part := range parts {
		line := strings.TrimSpace(string(part))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		_, ipnet, err := net.ParseCIDR(line)
		if err == nil {
			nets = append(nets, ipnet)
		}
	}
	return nets
}
