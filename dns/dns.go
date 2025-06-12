package dns

import (
	"context"
	"net"
)

func LookupAddrLocalDNS(addr string) ([]string, error) {
	r := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, network, address string) (net.Conn, error) {
			dialer := net.Dialer{}
			return dialer.DialContext(ctx, "udp", "127.0.0.1:53")
		},
	}
	return r.LookupAddr(context.Background(), addr)
}
