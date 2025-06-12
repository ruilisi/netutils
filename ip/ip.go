package ip

import (
	"encoding/binary"
	"errors"
	"fmt"
	"net"
	"strings"
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

func IP2CIDR(ip string) string {
	if !strings.Contains(ip, "/") {
		return ip + "/32"
	}
	return ip
}

// GetOutboundInterface returns the outbound interface
func GetOutboundInterface() (*net.Interface, error) {
	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}
	for _, iface := range ifaces {
		if iface.Name == "br0" || iface.Name == "br-lan" {
			return &iface, nil
		}
	}
	for _, iface := range ifaces {
		if iface.Name == "eth0" {
			return &iface, nil
		}
	}
	for _, iface := range ifaces {
		if iface.Name == "wlan0" {
			return &iface, nil
		}
	}
	return nil, errors.New("failed to find outbound interface")
}

func GetOutboundIP(iface *net.Interface) (string, error) {
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", errors.New("failed to find outbound ip")
}

func GetBroadcastIP() string {
	iface, err := GetOutboundInterface()
	if err != nil {
		return ""
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return ""
	}
	if len(addrs) == 0 {
		return ""
	}
	ipnet := addrs[0].(*net.IPNet)
	ip := ipnet.IP.To4()
	mask := ipnet.Mask
	bip := make(net.IP, len(ip))
	binary.BigEndian.PutUint32(bip, binary.BigEndian.Uint32(ip)|^binary.BigEndian.Uint32(mask))
	return bip.String()
}
