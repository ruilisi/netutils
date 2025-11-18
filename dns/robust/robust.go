package robust

import (
	"context"
	"errors"
	"net"
	"time"
)

// ResolveUDPAddr resolves a UDP server address using multiple DNS servers,
// racing queries and retrying. Example serverAddr: "example.com:12345".
func ResolveUDPAddr(serverAddr string, dnsServers []string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return nil, err
	}

	// If already an IP literal, no DNS needed.
	if ip := net.ParseIP(host); ip != nil {
		port, err := net.LookupPort("udp", portStr)
		if err != nil {
			return nil, err
		}
		return &net.UDPAddr{IP: ip, Port: port}, nil
	}

	const retries = 2

	var lastErr error
	for range retries {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		addr, err := resolveWithDNSServers(ctx, host, portStr, dnsServers)
		cancel()

		if err == nil {
			return addr, nil
		}
		lastErr = err
	}

	return nil, lastErr
}

// Query multiple DNS servers concurrently (racing)
func resolveWithDNSServers(ctx context.Context, host, port string, dnsServers []string) (*net.UDPAddr, error) {
	type result struct {
		addr *net.UDPAddr
		err  error
	}

	ch := make(chan result, len(dnsServers))

	for _, dns := range dnsServers {
		go func(dns string) {
			addr, err := resolveUsingDNS(ctx, dns, host, port)
			ch <- result{addr, err}
		}(dns)
	}

	for range dnsServers {
		select {
		case r := <-ch:
			if r.err == nil {
				return r.addr, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, errors.New("robustdns: all DNS servers failed")
}

// Send DNS query via custom resolver
func resolveUsingDNS(ctx context.Context, dns, host, port string) (*net.UDPAddr, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 800 * time.Millisecond}
			return d.DialContext(ctx, "udp", dns)
		},
	}

	ips, err := resolver.LookupIP(ctx, "ip", host)
	if err != nil || len(ips) == 0 {
		return nil, err
	}

	p, err := net.LookupPort("udp", port)
	if err != nil {
		return nil, err
	}

	return &net.UDPAddr{
		IP:   ips[0],
		Port: p,
	}, nil
}
