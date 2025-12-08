package robust

import (
	"context"
	"errors"
	"net"
	"strconv"
	"time"
)

// ResolveDomain resolves a domain name to an IP address using multiple DNS servers,
// racing queries and retrying. Returns the first successfully resolved IP.
func ResolveDomain(domain string, dnsServers []string) (net.IP, error) {
	// If already an IP literal, return it directly.
	if ip := net.ParseIP(domain); ip != nil {
		return ip, nil
	}

	const retries = 2

	var lastErr error
	for range retries {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		ip, err := resolveIPWithDNSServers(ctx, domain, dnsServers)
		cancel()

		if err == nil {
			return ip, nil
		}
		lastErr = err
	}

	return nil, lastErr
}

// ResolveUDPAddr resolves a UDP server address using multiple DNS servers,
// racing queries and retrying. Example serverAddr: "example.com:12345".
// This function is provided for backward compatibility and calls ResolveDomain internally.
func ResolveUDPAddr(serverAddr string, dnsServers []string) (*net.UDPAddr, error) {
	host, portStr, err := net.SplitHostPort(serverAddr)
	if err != nil {
		return nil, err
	}

	ip, err := ResolveDomain(host, dnsServers)
	if err != nil {
		return nil, err
	}

	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}

	return &net.UDPAddr{IP: ip, Port: port}, nil
}

// Query multiple DNS servers concurrently (racing)
func resolveIPWithDNSServers(ctx context.Context, domain string, dnsServers []string) (net.IP, error) {
	type result struct {
		ip  net.IP
		err error
	}

	ch := make(chan result, len(dnsServers))

	for _, dns := range dnsServers {
		go func(dns string) {
			ip, err := resolveUsingDNS(ctx, dns, domain)
			ch <- result{ip, err}
		}(dns)
	}

	for range dnsServers {
		select {
		case r := <-ch:
			if r.err == nil {
				return r.ip, nil
			}
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}

	return nil, errors.New("robustdns: all DNS servers failed")
}

// Send DNS query via custom resolver
func resolveUsingDNS(ctx context.Context, dns, domain string) (net.IP, error) {
	resolver := &net.Resolver{
		PreferGo: true,
		Dial: func(ctx context.Context, _, _ string) (net.Conn, error) {
			d := net.Dialer{Timeout: 800 * time.Millisecond}
			return d.DialContext(ctx, "udp", dns)
		},
	}

	ips, err := resolver.LookupIP(ctx, "ip", domain)
	if err != nil || len(ips) == 0 {
		return nil, err
	}

	return ips[0], nil
}
