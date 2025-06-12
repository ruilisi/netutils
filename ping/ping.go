package ping

import (
	"math/rand"
	"net"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

func FastPing(addr string, timeout time.Duration) error {
	c, err := icmp.ListenPacket("ip4:icmp", "")
	if err != nil {
		return err
	}
	defer c.Close()

	dst, err := net.ResolveIPAddr("ip4", addr)
	if err != nil {
		return err
	}

	id := rand.Intn(65535)
	seq := 1
	buf := make([]byte, 128)
	m := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: id, Seq: seq,
			Data: buf[:56],
		},
	}
	b, err := m.Marshal(nil)
	if err != nil {
		return err
	}

	_, err = c.WriteTo(b, dst)
	if err != nil {
		return err
	}

	err = c.SetReadDeadline(time.Now().Add(timeout))
	if err != nil {
		return err
	}
	for {
		_, peer, err := c.ReadFrom(buf)
		if err != nil {
			return err
		}
		// simply check if peer equals addr
		if peer.String() == addr {
			return nil
		}
	}
}
