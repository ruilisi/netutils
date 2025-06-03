package ip

import (
	"fmt"
	"net"
)

func IsIPV6(ip *net.IP) bool {
	return ip.To4() == nil && ip.To16() != nil
}

func IsIPNetV6(cidr *net.IPNet) bool {
	return IsIPV6(&cidr.IP)
}

func IsIPNetStrV6B(ipNetStr string) bool {
	_, ipNet, err := net.ParseCIDR(ipNetStr)
	if err != nil {
		return false
	}
	return IsIPNetV6(ipNet)
}

func IsIPNetStrV6(ipNetStr string) (bool, error) {
	_, ipNet, err := net.ParseCIDR(ipNetStr)
	if err != nil {
		return false, err
	}
	return IsIPNetV6(ipNet), nil
}

func IP2IPNetFullMask(ip net.IP) net.IPNet {
	maskLen := 32
	if IsIPV6(&ip) {
		maskLen = 128
	}

	return net.IPNet{
		IP:   ip,
		Mask: net.CIDRMask(maskLen, maskLen),
	}
}
func IPStrFullMask(ipStr string) (string, error) {
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return "", fmt.Errorf("invalid IP: %s", ipStr)
	}
	if ip.To4() != nil {
		return ipStr + "/32", nil
	}
	return ipStr + "/128", nil
}

// IsDefaultIPNet determines if the ip net is default, "0.0.0.0/0" or "::/0
func IsDefaultIPNet(ipnet *net.IPNet) bool {
	ones, _ := ipnet.Mask.Size()
	return IsDefaultIP(ipnet.IP) && ones == 0
}

// IsDefaultIP determines if the ip is default, "0.0.0.0" or "::"
func IsDefaultIP(ip net.IP) bool {
	return (ip.Equal(net.IPv4zero) || ip.Equal(net.IPv6zero))
}
