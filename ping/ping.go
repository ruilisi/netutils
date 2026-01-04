package ping

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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

// PingCmd invokes ping command under the hood
// **Successful ping result**
/*
PING 39.156.66.11 (39.156.66.11) 56(84) bytes of data.
64 bytes from 39.156.66.11: icmp_seq=1 ttl=52 time=44.7 ms

--- 39.156.66.11 ping statistics ---
1 packets transmitted, 1 received, 0% packet loss, time 0ms
rtt min/avg/max/mdev = 44.753/44.753/44.753/0.000 ms
*/
// **Unsuccessful ping result**
/*
PING 40.156.66.11 (40.156.66.11) 56(84) bytes of data.

--- 40.156.66.11 ping statistics ---
1 packets transmitted, 0 received, 100% packet loss, time 0ms
*/
func PingCmd(target net.IP, timeout time.Duration) (time.Duration, error) {
	ctx, cancel := context.WithTimeout(context.Background(), timeout+time.Millisecond*50)
	defer cancel()

	cmd := exec.CommandContext(ctx, "ping", "-c", "1", "-W", strconv.Itoa(int(timeout/time.Second)), target.String())
	outputBytes, err := cmd.CombinedOutput()
	if err != nil {
		return -1, err
	}
	output := string(outputBytes)
	start := strings.Index(output, "rtt min/avg/max/mdev = ")
	if start == -1 {
		return -1, errors.New("rtt timeout")
	}
	parts := strings.Split(output[start+len("rtt min/avg/max/mdev = "):], "/")
	if len(parts) == 0 {
		return -1, errors.New("ping unavailable")
	}
	pingResult, err := strconv.ParseFloat(parts[0], 32)
	if err != nil {
		return -1, err
	}
	return time.Duration(pingResult) * time.Millisecond, nil
}

// Ping is like regular ping command, sends ICMP packet, requires privileged permission, and returns RTT
func Ping(target net.IP, timeout time.Duration) (time.Duration, error) {
	if target == nil {
		return 0, errors.New("nil target IP")
	}

	var (
		network  string
		icmpType icmp.Type
		protocol int
		dst      net.Addr
	)

	if target.To4() != nil {
		network = "ip4:icmp"
		icmpType = ipv4.ICMPTypeEcho
		protocol = 1
		dst = &net.IPAddr{IP: target}
	} else {
		network = "ip6:ipv6-icmp"
		icmpType = ipv6.ICMPTypeEchoRequest
		protocol = 58
		dst = &net.IPAddr{IP: target}
	}

	conn, err := icmp.ListenPacket(network, "")
	if err != nil {
		return 0, err
	}
	defer conn.Close()

	// Generate unique ID by combining PID with random value to reduce collision probability
	// This is important when multiple ping operations run concurrently
	id := (os.Getpid() & 0xffff) ^ (rand.Intn(0xffff))
	// Randomize sequence number for additional uniqueness
	seq := rand.Intn(0xffff)

	msg := icmp.Message{
		Type: icmpType,
		Code: 0,
		Body: &icmp.Echo{
			ID:   id,
			Seq:  seq,
			Data: []byte("PING"),
		},
	}

	b, err := msg.Marshal(nil)
	if err != nil {
		return 0, err
	}

	start := time.Now()
	deadline := start.Add(timeout)

	if _, err := conn.WriteTo(b, dst); err != nil {
		return 0, err
	}

	// Read loop to filter out spurious ICMP packets
	// Since raw ICMP sockets receive ALL ICMP traffic for the protocol,
	// we need to filter for packets matching our specific ID and sequence number
	reply := make([]byte, 1500)
	for {
		// Update deadline for each read attempt to ensure accurate timeout
		if err := conn.SetDeadline(deadline); err != nil {
			return 0, err
		}

		n, _, err := conn.ReadFrom(reply)
		if err != nil {
			// Timeout or other read error
			return 0, err
		}

		rm, err := icmp.ParseMessage(protocol, reply[:n])
		if err != nil {
			// Ignore malformed packets and continue reading
			continue
		}

		switch rm.Type {
		case ipv4.ICMPTypeEchoReply, ipv6.ICMPTypeEchoReply:
			body, ok := rm.Body.(*icmp.Echo)
			if !ok {
				// Invalid echo reply structure, continue reading
				continue
			}
			// Only accept replies matching our request
			if body.ID == id && body.Seq == seq {
				return time.Since(start), nil
			}
			// ID/Seq mismatch (likely from another ping), continue reading
		default:
			// Ignore other ICMP types (destination unreachable, time exceeded, etc.)
			continue
		}

		// Check if we've exceeded timeout while filtering packets
		if time.Now().After(deadline) {
			return 0, errors.New("timeout waiting for matching ICMP reply")
		}
	}
}
