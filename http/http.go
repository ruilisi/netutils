package http

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"
)

type ReadCounterConn struct {
	net.Conn
	Downloaded int64
}

func (r *ReadCounterConn) Read(p []byte) (int, error) {
	n, err := r.Conn.Read(p)
	r.Downloaded += int64(n)
	fmt.Printf("Downloaded: %.2f KB\n", float64(r.Downloaded)/1024)
	return n, err
}

// BuildRawRequest builds a raw HTTP request and return the dumped bytes
func BuildRawRequest(url string, headers map[string]string) ([]byte, error) {
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}

	// Extract host and port
	host := req.URL.Host
	if !strings.Contains(host, ":") {
		host += ":80" // assume HTTP
	}

	// Set headers
	for k, v := range headers {
		if k == "Host" {
			req.Host = v
		} else {
			req.Header.Set(k, v)
		}
	}

	reqBytes, err := httputil.DumpRequestOut(req, false) // false = don't include body
	if err != nil {
		return nil, err
	}
	return reqBytes, nil
}

// DownloadSpeedTCP send the request over TCP and measure download speed for duration
func DownloadSpeedTCP(conn net.Conn, reqBytes []byte, duration time.Duration) (float64, error) {
	// conn = &ReadCounterConn{Conn: conn}
	defer conn.Close()

	conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
	if _, err := conn.Write(reqBytes); err != nil {
		return 0, err
	}

	reader := bufio.NewReader(conn)
	resp, err := http.ReadResponse(reader, nil)
	if err != nil {
		return 0, err
	}
	defer resp.Body.Close()

	var total int64
	buf := make([]byte, 32*1024)
	start := time.Now()
	timeout := time.After(duration)

	for {
		select {
		case <-timeout:
			return float64(total) / duration.Seconds(), nil
		default:
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := resp.Body.Read(buf)
			if n > 0 {
				total += int64(n)
			}
			if err != nil {
				if err == io.EOF {
					return float64(total) / time.Since(start).Seconds(), nil
				}
			}
		}
	}
}

func HostPortFromURL(rawURL string) (string, *url.URL, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return "", nil, err
	}
	port := u.Port()
	if port == "" {
		if u.Scheme == "https" {
			port = "443"
		} else {
			port = "80"
		}
	}
	return u.Hostname() + ":" + port, u, nil
}
