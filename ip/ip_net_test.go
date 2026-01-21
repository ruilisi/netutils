package ip

import (
	"testing"
)

func TestStrToIPNets(t *testing.T) {
	tests := []struct {
		name      string
		routes    string
		delimiter string
		wantCount int
	}{
		{"single CIDR", "10.0.0.0/8", ",", 1},
		{"multiple CIDRs", "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16", ",", 3},
		{"with spaces", "10.0.0.0/8 , 172.16.0.0/12", ",", 2},
		{"newline delimiter", "10.0.0.0/8\n172.16.0.0/12", "\n", 2},
		{"invalid CIDR skipped", "10.0.0.0/8,invalid,192.168.0.0/16", ",", 2},
		{"empty string", "", ",", 0},
		{"IPv6", "2001:db8::/32,fc00::/7", ",", 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := StrToIPNets(tt.routes, tt.delimiter)
			if len(result) != tt.wantCount {
				t.Errorf("StrToIPNets() returned %d networks, want %d", len(result), tt.wantCount)
			}
		})
	}
}

func TestBytesToIPNets(t *testing.T) {
	tests := []struct {
		name      string
		data      []byte
		sep       []byte
		wantCount int
	}{
		{"single CIDR", []byte("10.0.0.0/8"), []byte("\n"), 1},
		{"multiple lines", []byte("10.0.0.0/8\n172.16.0.0/12"), []byte("\n"), 2},
		{"with comments", []byte("10.0.0.0/8\n# comment\n172.16.0.0/12"), []byte("\n"), 2},
		{"empty lines skipped", []byte("10.0.0.0/8\n\n172.16.0.0/12"), []byte("\n"), 2},
		{"invalid skipped", []byte("10.0.0.0/8\ninvalid\n172.16.0.0/12"), []byte("\n"), 2},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := BytesToIPNets(tt.data, tt.sep)
			if len(result) != tt.wantCount {
				t.Errorf("BytesToIPNets() returned %d networks, want %d", len(result), tt.wantCount)
			}
		})
	}
}

func BenchmarkStrToIPNets(b *testing.B) {
	routes := "10.0.0.0/8,172.16.0.0/12,192.168.0.0/16,fc00::/7,fe80::/10"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		StrToIPNets(routes, ",")
	}
}

func BenchmarkBytesToIPNets(b *testing.B) {
	data := []byte("10.0.0.0/8\n172.16.0.0/12\n192.168.0.0/16\nfc00::/7\nfe80::/10")
	sep := []byte("\n")
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		BytesToIPNets(data, sep)
	}
}
