package dns

import (
	"net"

	"github.com/miekg/dns"
)

// DNSExchangeRawLocally handles common DNS queries like nslookup
func DNSExchangeRawLocally(pkt []byte) ([]byte, error) {
	msg := new(dns.Msg)
	if err := msg.Unpack(pkt); err != nil {
		return nil, err
	}

	reply := new(dns.Msg)
	reply.SetReply(msg)

	for _, q := range msg.Question {
		switch q.Qtype {
		case dns.TypeA:
			addARecords(reply, q)
		case dns.TypeAAAA:
			addAAAARecords(reply, q)
		case dns.TypeCNAME:
			addCNAMERecords(reply, q)
		case dns.TypeMX:
			addMXRecords(reply, q)
		case dns.TypeTXT:
			addTXTRecords(reply, q)
		case dns.TypeNS:
			addNSRecords(reply, q)
		default:
			reply.Rcode = dns.RcodeNotImplemented
		}
	}

	return reply.Pack()
}

// helper functions
func addARecords(reply *dns.Msg, q dns.Question) {
	ips, _ := net.LookupHost(q.Name)
	for _, ip := range ips {
		if ip4 := net.ParseIP(ip).To4(); ip4 != nil {
			reply.Answer = append(reply.Answer, &dns.A{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeA, Class: dns.ClassINET, Ttl: 300},
				A:   ip4,
			})
		}
	}
}

func addAAAARecords(reply *dns.Msg, q dns.Question) {
	ips, _ := net.LookupIP(q.Name)
	for _, ip := range ips {
		if ip.To4() == nil { // only IPv6
			reply.Answer = append(reply.Answer, &dns.AAAA{
				Hdr:  dns.RR_Header{Name: q.Name, Rrtype: dns.TypeAAAA, Class: dns.ClassINET, Ttl: 300},
				AAAA: ip,
			})
		}
	}
}

func addCNAMERecords(reply *dns.Msg, q dns.Question) {
	if cname, err := net.LookupCNAME(q.Name); err == nil {
		reply.Answer = append(reply.Answer, &dns.CNAME{
			Hdr:    dns.RR_Header{Name: q.Name, Rrtype: dns.TypeCNAME, Class: dns.ClassINET, Ttl: 300},
			Target: cname,
		})
	}
}

func addMXRecords(reply *dns.Msg, q dns.Question) {
	if mxs, err := net.LookupMX(q.Name); err == nil {
		for _, mx := range mxs {
			reply.Answer = append(reply.Answer, &dns.MX{
				Hdr:        dns.RR_Header{Name: q.Name, Rrtype: dns.TypeMX, Class: dns.ClassINET, Ttl: 300},
				Preference: mx.Pref,
				Mx:         mx.Host,
			})
		}
	}
}

func addTXTRecords(reply *dns.Msg, q dns.Question) {
	if txts, err := net.LookupTXT(q.Name); err == nil {
		for _, txt := range txts {
			reply.Answer = append(reply.Answer, &dns.TXT{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeTXT, Class: dns.ClassINET, Ttl: 300},
				Txt: []string{txt},
			})
		}
	}
}

func addNSRecords(reply *dns.Msg, q dns.Question) {
	if nss, err := net.LookupNS(q.Name); err == nil {
		for _, ns := range nss {
			reply.Answer = append(reply.Answer, &dns.NS{
				Hdr: dns.RR_Header{Name: q.Name, Rrtype: dns.TypeNS, Class: dns.ClassINET, Ttl: 300},
				Ns:  ns.Host,
			})
		}
	}
}
