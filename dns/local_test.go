package dns

import (
	"testing"

	"github.com/miekg/dns"
)

// helper to build a query packet
func buildQuery(name string, qtype uint16) []byte {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(name), qtype)
	msg.RecursionDesired = true
	queryBytes, _ := msg.Pack()
	return queryBytes
}

// helper to unpack response
func unpackResponse(pkt []byte) (*dns.Msg, error) {
	msg := new(dns.Msg)
	err := msg.Unpack(pkt)
	return msg, err
}

func TestDNSExchangeRawLocally(t *testing.T) {
	tests := []struct {
		name  string
		qtype uint16
	}{
		{"baidu.com.", dns.TypeA},
		// {"baidu.com.", dns.TypeAAAA},
		{"baidu.com.", dns.TypeCNAME},
		{"baidu.com.", dns.TypeMX},
		{"baidu.com.", dns.TypeTXT},
		{"baidu.com.", dns.TypeNS},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			query := buildQuery(tt.name, tt.qtype)
			resp, err := ExchangeRawLocal(query)
			if err != nil {
				t.Fatalf("DNSExchangeRawLocally returned error: %v", err)
			}
			if resp.Rcode != dns.RcodeSuccess && resp.Rcode != dns.RcodeNameError {
				t.Errorf("unexpected RCODE: %d", resp.Rcode)
			}

			if resp.Rcode == dns.RcodeSuccess && len(resp.Answer) == 0 {
				t.Errorf("expected at least 1 answer for query type %d", tt.qtype)
			}

			// Optional: print answers for manual inspection
			for _, ans := range resp.Answer {
				t.Logf("Answer: %s", ans.String())
			}
		})
	}
}

func TestUnsupportedType(t *testing.T) {
	// Use a query type that is not implemented (e.g., SRV)
	query := buildQuery("baidu.com.", dns.TypeSRV)
	resp, err := ExchangeRawLocal(query)
	if err != nil {
		t.Fatalf("DNSExchangeRawLocally returned error: %v", err)
	}
	if resp.Rcode != dns.RcodeNotImplemented {
		t.Errorf("expected RCODE NotImplemented, got %d", resp.Rcode)
	}
}
