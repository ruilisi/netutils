package dns

import (
	"encoding/hex"
	"testing"

	"github.com/miekg/dns"
)

// TestBadRdataIssue reproduces the "dns: bad rdata" error from the packet dump
func TestBadRdataIssue(t *testing.T) {
	// This is the actual packet from the error log, starting at the DNS payload
	// Frame shows offset 32 (0x20) is where UDP payload starts after IPv6 headers
	hexDump := `A5 87 01 00 00 01 00 00 00 00 00 00 11 31 39 35 35 36 38 2D 69 70 76 34 66 64 73 6D 74 65 02 67 72 06 67 6C 6F 62 61 6C 05 61 61 2D 72 74 0A 73 68 61 72 65 70 6F 69 6E 74 03 63 6F 6D 00 00 1C 00 01`

	// Remove spaces
	hexStr := ""
	for _, c := range hexDump {
		if c != ' ' {
			hexStr += string(c)
		}
	}

	pkt, err := hex.DecodeString(hexStr)
	if err != nil {
		t.Fatalf("Failed to decode hex: %v", err)
	}

	t.Logf("Packet length: %d bytes", len(pkt))
	t.Logf("Packet hex: %x", pkt)

	// Try to parse with miekg/dns
	msg := new(dns.Msg)
	err = msg.Unpack(pkt)
	if err != nil {
		t.Logf("Unpack error: %v", err)
		t.Logf("This is the error we're seeing in production")
	} else {
		t.Logf("Successfully unpacked DNS message")
		t.Logf("Questions: %v", msg.Question)
	}

	// Also test with ExchangeRawLocal
	resMsg, err := ExchangeRawLocal(pkt)
	if err != nil {
		t.Errorf("ExchangeRawLocal failed: %v", err)
	} else {
		t.Logf("ExchangeRawLocal succeeded: %v", resMsg)
	}
}
