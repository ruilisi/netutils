//go:build !((windows || linux) && cgo)

package reservedip

import (
	"net"
	"sync"
)

var (
	reservedIPv4Networks []*net.IPNet
	reservedIPv6Networks []*net.IPNet
	initOnce             sync.Once
)

// initReservedNetworks initializes the reduced set of reserved IP ranges
// (only those not already covered by ip.IsPrivate(), ip.IsLoopback(), ip.IsLinkLocalUnicast())
func initReservedNetworks() {
	// IPv4 reserved CIDR ranges (reduced set - excluding stdlib-covered ranges)
	ipv4CIDRs := []string{
		"0.0.0.0/8",       // Current network (default route)
		"100.64.0.0/10",   // Shared address space (carrier-grade NAT)
		"192.0.0.0/29",    // IPv4 special purpose
		"192.0.2.0/24",    // TEST-NET-1 (documentation examples)
		"192.88.99.0/24",  // 6to4 relay anycast
		"198.18.0.0/15",   // Network benchmarking
		"198.51.100.0/24", // TEST-NET-2 (documentation examples)
		"203.0.113.0/24",  // TEST-NET-3 (documentation examples)
		"224.0.0.0/3",     // Multicast addresses (224.0.0.0/4 and higher)
	}

	// IPv6 reserved CIDR ranges (reduced set - excluding stdlib-covered ranges)
	ipv6CIDRs := []string{
		"::/128",        // IPv6 unspecified address
		"::ffff:0:0/96", // IPv4-mapped addresses
		"100::/64",      // Discard prefix
		"2001::/32",     // Teredo tunneling
		"2001:10::/28",  // ORCHID (old)
		"2001:20::/28",  // ORCHIDv2
		"2001:db8::/32", // Documentation example addresses
		"ff00::/8",      // IPv6 multicast addresses
	}

	// Parse IPv4 CIDRs
	for _, cidr := range ipv4CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue // Skip invalid CIDR (should not happen)
		}
		reservedIPv4Networks = append(reservedIPv4Networks, ipNet)
	}

	// Parse IPv6 CIDRs
	for _, cidr := range ipv6CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			continue // Skip invalid CIDR (should not happen)
		}
		reservedIPv6Networks = append(reservedIPv6Networks, ipNet)
	}
}

// IsReservedIP checks if IP is in reserved address ranges (supports IPv4 and IPv6)
func IsReservedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check IsPrivate, IsLoopback, IsLinkLocalUnicast (stdlib optimized methods)
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}

	// Initialize reserved networks once
	initOnce.Do(initReservedNetworks)

	// Check IPv4 reserved addresses
	if ipv4 := ip.To4(); ipv4 != nil {
		for _, ipNet := range reservedIPv4Networks {
			if ipNet.Contains(ipv4) {
				return true
			}
		}
		return false
	}

	// Check IPv6 reserved addresses
	if ipv6 := ip.To16(); ipv6 != nil {
		for _, ipNet := range reservedIPv6Networks {
			if ipNet.Contains(ipv6) {
				return true
			}
		}
	}

	return false
}
