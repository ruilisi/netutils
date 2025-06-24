package ip

import (
	"net"
	"testing"
)

func TestIsPrivateNetwork(t *testing.T) {
	tests := []struct {
		cidr    string
		private bool
	}{
		// IPv4 private networks
		{"10.0.0.0/8", true},
		{"172.16.0.0/12", true},
		{"192.168.0.0/16", true},
		// IPv4 subnets within private ranges
		{"10.1.2.3/24", true},
		{"172.16.1.0/24", true},
		{"192.168.1.0/24", true},
		// IPv6 private network
		{"fc00::/7", true},
		{"fd00::/8", true},
		// IPv6 subnets within private range
		{"fc00::1/128", true},
		// Public networks
		{"8.8.8.8/32", false},
		{"2001:db8::/32", false},
		// Edge cases
		{"0.0.0.0/0", false},
		{"::/0", false},
		{"fe80::/64", true},      // Link-Local
		{"169.254.0.0/16", true}, // IPv4 link-local
		{"::1/128", true},        // v6 loopback
		{"127.0.0.1/32", true},   // v4 loopback
	}

	for _, tt := range tests {
		_, ipnet, err := net.ParseCIDR(tt.cidr)
		if err != nil {
			t.Errorf("Failed to parse CIDR %s: %v", tt.cidr, err)
			continue
		}

		t.Logf("ipnet: %+v", ipnet)
		got := IsPrivateNetwork(ipnet)
		if got != tt.private {
			t.Errorf("isPrivateNetwork(%s) = %v, want %v", tt.cidr, got, tt.private)
		}
	}
}

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		ip      string
		private bool
	}{
		// IPv4 private addresses
		{"10.0.0.1", true},
		{"172.16.0.1", true},
		{"172.31.255.255", true}, // upper bound of 172.16.0.0/12
		{"192.168.1.1", true},
		// IPv4 public addresses
		{"8.8.8.8", false},
		{"1.1.1.1", false},
		{"172.15.255.255", false}, // just below 172.16.0.0/12
		{"172.32.0.1", false},     // just above 172.31.255.255
		// IPv6 private addresses
		{"fc00::1", true},
		{"fd12:3456:789a:1::1", true},
		// IPv6 public addresses
		{"2001:db8::1", false},
		{"::1", true}, // loopback
		// Special cases
		{"127.0.0.1", true},       // loopback
		{"169.254.0.1", true},     // link-local
		{"::ffff:10.0.0.1", true}, // IPv4-mapped IPv6 address
	}

	for _, tt := range tests {
		ip := net.ParseIP(tt.ip)
		if ip == nil {
			t.Errorf("Failed to parse IP %s", tt.ip)
			continue
		}

		got := IsPrivateIP(ip)
		if got != tt.private {
			t.Errorf("isPrivateIP(%s) = %v, want %v", tt.ip, got, tt.private)
		}
	}
}

func TestEdgeCases(t *testing.T) {
	// Test nil IPNet
	if IsPrivateNetwork(nil) != false {
		t.Error("nil IPNet should not be private")
	}

	// Test nil IP
	if IsPrivateIP(nil) != false {
		t.Error("nil IP should not be private")
	}

	// Test invalid IP
	invalidIP := net.IP("not an ip")
	if IsPrivateIP(invalidIP) != false {
		t.Error("invalid IP should not be private")
	}
}
