package ip

import (
	"fmt"
	"net"
	"testing"
)

func TestAddFullMask(t *testing.T) {
	tests := []struct {
		ip      string
		maskLen int
	}{
		{"192.168.1.0", 32},
		{"fe80::", 128},
	}

	for _, tt := range tests {
		t.Run(tt.ip, func(t *testing.T) {
			ip := net.ParseIP(tt.ip)
			cidr := IP2IPNetFullMask(ip)

			if cidr.String() != fmt.Sprintf("%s/%d", tt.ip, tt.maskLen) {
				t.Errorf("IPWithFullMask failed for %s", tt.ip)
			}
		})
	}
}

func TestIsCIDRStrV6(t *testing.T) {
	tests := []struct {
		cidr    string
		want    bool
		wantErr bool
	}{
		// Valid IPv4 CIDRs
		{"192.168.1.0/24", false, false},
		{"10.0.0.0/8", false, false},
		{"0.0.0.0/0", false, false},

		// Valid IPv6 CIDRs
		{"2001:db8::/32", true, false},
		{"::1/128", true, false},
		{"fe80::/10", true, false},

		// Edge cases
		{"", false, true},               // empty string
		{"not.a.cidr", false, true},     // invalid format
		{"192.168.1.1", false, true},    // missing mask
		{"2001:db8::1", false, true},    // missing mask
		{"192.168.1.0/33", false, true}, // invalid IPv4 mask
		{"2001:db8::/129", false, true}, // invalid IPv6 mask
	}

	for _, tt := range tests {
		t.Run(tt.cidr, func(t *testing.T) {
			got, err := IsIPNetStrV6(tt.cidr)
			if (err != nil) != tt.wantErr {
				t.Errorf("IsIPv6CIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if got != tt.want {
				t.Errorf("IsIPv6CIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestIsDefaultRoute(t *testing.T) {
	tests := []struct {
		ipnetStr string
		want     bool
	}{
		{"0.0.0.0/0", true},
		{"::/0", true},
		{"0.0.0.0/2", false},
		{"8.8.8.8/32", false},
		{"2001:db8::/32", false},
	}

	for _, tt := range tests {
		t.Run(tt.ipnetStr, func(t *testing.T) {
			_, ipnet, _ := net.ParseCIDR(tt.ipnetStr)
			if IsDefaultIPNet(ipnet) != tt.want {
				t.Errorf("failed to test default route for %s", tt.ipnetStr)
			}
		})
	}
}

func TestEqualIPNet(t *testing.T) {
	tests := []struct {
		a      string
		b      string
		expect bool
	}{
		{"192.168.1.0/24", "192.168.1.0/24", true},
		{"192.168.1.10/24", "192.168.1.0/24", true}, // masked IPs still same subnet
		{"192.168.1.0/24", "192.168.2.0/24", false},
		{"192.168.1.0/24", "192.168.1.0/25", false},
		{"240e:3a1:4c21:e310::/64", "240e:3a1:4c21:e310::/64", true},
		{"240e:3a1:4c21:e310::1/64", "240e:3a1:4c21:e310::/64", true},
		{"240e:3a1:4c21:e310::/64", "240e:3a1:4c21::/56", false},
		{"240e:3a1:4c21:e310::/32", "240e:3a1:4c21::/32", true},
	}

	for _, tt := range tests {
		_, netA, errA := net.ParseCIDR(tt.a)
		_, netB, errB := net.ParseCIDR(tt.b)
		if errA != nil || errB != nil {
			t.Fatalf("failed to parse CIDRs %q or %q", tt.a, tt.b)
		}

		if got := EqualIPNet(netA, netB); got != tt.expect {
			t.Errorf("EqualIPNet(%q, %q) = %v; want %v", tt.a, tt.b, got, tt.expect)
		}
	}
}

func TestGetOutboundInterface(t *testing.T) {
	iface, err := GetOutboundInterface()
	if err != nil {
		t.Fatalf("GetOutboundInterface failed: %v", err)
	}
	if iface == nil {
		t.Fatal("expected non-nil interface, got nil")
	}

	addrs, err := iface.Addrs()
	if err != nil {
		t.Fatalf("failed to get addresses for iface %s: %v", iface.Name, err)
	}
	if len(addrs) == 0 {
		t.Fatalf("interface %s has no addresses", iface.Name)
	}

	t.Logf("Outbound interface: %s (%v)", iface.Name, addrs)
}
