package ip

import (
	"errors"
	"net"
	"time"
)

// GetOutboundInterface detects the outbound interface by racing two common DNS servers.
func GetOutboundInterface() (*net.Interface, error) {
	targets := []string{"8.8.8.8:53", "114.114.114.114:53"}
	type result struct {
		iface *net.Interface
		err   error
	}

	ch := make(chan result, len(targets))

	for _, target := range targets {
		go func(tgt string) {
			iface, err := getInterfaceViaTarget(tgt)
			ch <- result{iface: iface, err: err}
		}(target)
	}

	timeout := time.After(2 * time.Second) // fail fast if network broken

	for range targets {
		select {
		case res := <-ch:
			if res.err == nil && res.iface != nil {
				return res.iface, nil
			}
		case <-timeout:
			return nil, errors.New("timeout detecting outbound interface")
		}
	}

	return nil, errors.New("failed to find outbound interface")
}

func getInterfaceViaTarget(target string) (*net.Interface, error) {
	conn, err := net.Dial("udp", target)
	if err != nil {
		return nil, err
	}
	defer conn.Close()

	localAddr := conn.LocalAddr().(*net.UDPAddr)

	ifaces, err := net.Interfaces()
	if err != nil {
		return nil, err
	}

	for _, iface := range ifaces {
		addrs, _ := iface.Addrs()
		for _, addr := range addrs {
			var ip net.IP
			switch v := addr.(type) {
			case *net.IPNet:
				ip = v.IP
			case *net.IPAddr:
				ip = v.IP
			}
			if ip != nil && ip.Equal(localAddr.IP) {
				return &iface, nil
			}
		}
	}

	return nil, errors.New("could not match local address to interface")
}

var (
	ErrNilIface = errors.New("interface is nil")
)

func GetOutboundIPNet(iface *net.Interface) (*net.IPNet, error) {
	if iface == nil {
		return nil, ErrNilIface
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return nil, err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			return ipnet, nil
		}
	}
	return nil, errors.New("failed to find outbound ip")
}

func GetOutboundIP(iface *net.Interface) (string, error) {
	if iface == nil {
		return "", ErrNilIface
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}
	for _, addr := range addrs {
		if ipnet, ok := addr.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			if ipnet.IP.To4() != nil {
				return ipnet.IP.String(), nil
			}
		}
	}
	return "", errors.New("failed to find outbound ip")
}
