package ip

import (
	"net"
)

var privateCIDRs = []*net.IPNet{}

func init() {
	for _, cidr := range []string{
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"fc00::/7", // IPv6 Unique Local Address
	} {
		_, ipnet, err := net.ParseCIDR(cidr)
		if err == nil {
			privateCIDRs = append(privateCIDRs, ipnet)
		}
	}
}

func IsPrivateNetwork(ipnet *net.IPNet) bool {
	if ipnet == nil {
		return false
	}
	for _, cidr := range privateCIDRs {
		if cidr.Contains(ipnet.IP) {
			return true
		}
	}
	return false
}

func IsPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
		return true
	}

	if ip4 := ip.To4(); ip4 != nil {
		return ip4[0] == 10 || // 10.0.0.0/8
			(ip4[0] == 172 && ip4[1] >= 16 && ip4[1] <= 31) || // 172.16.0.0/12
			(ip4[0] == 192 && ip4[1] == 168) // 192.168.0.0/16
	}

	return len(ip) == net.IPv6len && ip[0]&0xfe == 0xfc // fc00::/7
}
