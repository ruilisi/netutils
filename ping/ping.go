package ping

import (
	"context"
	"errors"
	"math/rand"
	"net"
	"os/exec"
	"strconv"
	"strings"
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
