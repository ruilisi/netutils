package reservedip

import (
	"net"
	"testing"
)

func TestIsReservedIP(t *testing.T) {
	tests := []struct {
		name     string
		ip       string
		expected bool
	}{
		// Test cases that should return true (stdlib-covered)
		{"Private 10.0.0.1", "10.0.0.1", true},
		{"Private 192.168.1.1", "192.168.1.1", true},
		{"Private 172.16.0.1", "172.16.0.1", true},
		{"Loopback IPv4", "127.0.0.1", true},
		{"Loopback IPv6", "::1", true},
		{"Link Local IPv4", "169.254.1.1", true},
		{"Link Local IPv6", "fe80::1", true},
		{"Private IPv6", "fc00::1", true},
		{"Google LLC", "142.250.197.0", false},
		{"192.0.0.0/29", "192.0.0.1", true},
		// Test cases that should return true (reduced set)
		{"Current network", "0.0.0.1", true},
		{"Shared address space", "100.64.0.1", true},
		{"TEST-NET-1", "192.0.2.1", true},
		{"6to4 relay", "192.88.99.1", true},
		{"Benchmarking", "198.18.0.1", true},
		{"TEST-NET-2", "198.51.100.1", true},
		{"TEST-NET-3", "203.0.113.1", true},
		{"Multicast", "224.0.0.1", true},
		{"IPv6 unspecified", "::", true},
		{"IPv4-mapped", "::ffff:192.0.2.1", true},
		{"Discard prefix", "100::1", true},
		{"Teredo", "2001::1", true},
		{"ORCHID", "2001:10::1", true},
		{"ORCHIDv2", "2001:20::1", true},
		{"IPv6 documentation", "2001:db8::1", true},
		{"IPv6 multicast", "ff00::1", true},

		// Test cases that should return false (public IPs)
		{"Google DNS", "8.8.8.8", false},
		{"Cloudflare DNS", "1.1.1.1", false},
		{"Public IPv6", "2001:4860:4860::8888", false},
		{"Regular public", "93.184.216.34", false},

		// Edge cases
		{"Nil IP", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var ip net.IP
			if tt.ip != "" {
				ip = net.ParseIP(tt.ip)
				if ip == nil {
					t.Fatalf("Failed to parse IP: %s", tt.ip)
				}
			}

			result := IsReservedIP(ip)
			if result != tt.expected {
				t.Errorf("IsReservedIP(%s) = %v, want %v", tt.ip, result, tt.expected)
			}
		})
	}
}

func TestIsReservedIPNil(t *testing.T) {
	result := IsReservedIP(nil)
	if result != false {
		t.Errorf("IsReservedIP(nil) = %v, want false", result)
	}
}
