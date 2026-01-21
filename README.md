# netutils

A comprehensive network utility toolkit written in Go for network diagnostics, packet analysis, and protocol handling.

## Features

- **Cross-platform** - Supports Windows, macOS, and Linux
- **IPv4/IPv6** - Full dual-stack support throughout
- **Zero dependencies** for core functionality (optional DNS library for advanced features)
- **Type-safe** - Leverages Go generics where appropriate

## Installation

```bash
go get github.com/ruilisi/netutils
```

Requires Go 1.23+

## Packages

| Package | Description |
|---------|-------------|
| [`device`](#device) | Device identification |
| [`dns`](#dns) | DNS resolution and packet analysis |
| [`ds`](#ds) | Data structures (generic Set) |
| [`http`](#http) | HTTP utilities and speed testing |
| [`ip`](#ip) | IP address handling, packet parsing, and manipulation |
| [`ping`](#ping) | ICMP ping and reachability checks |
| [`tcp`](#tcp) | TCP connection utilities |
| [`tun`](#tun) | TUN device support |
| [`util`](#util) | Hex dump and conversion utilities |

---

## device

Device identification utilities.

### GetUniqID

Returns a stable unique device identifier based on hardware (MAC address hash on macOS/Linux, hardware ID on Windows), with fallback to a persistent random ID.

```go
import "github.com/ruilisi/netutils/device"

id := device.GetUniqID()
fmt.Println(id) // e.g., "a1b2c3d4e5f6"
```

---

## dns

DNS resolution and packet analysis utilities.

### IsLikelyDNSPacket

Validates if a raw UDP payload appears to be a DNS packet.

```go
import "github.com/ruilisi/netutils/dns"

if dns.IsLikelyDNSPacket(udpPayload) {
    // Process DNS packet
}
```

### dns/robust

Robust DNS resolution with multiple servers, racing, and retry logic.

```go
import "github.com/ruilisi/netutils/dns/robust"

// Resolve using multiple DNS servers
ip, err := robust.ResolveDomain("example.com", []string{"8.8.8.8:53", "1.1.1.1:53"})
```

### dns/servers

Pre-configured DNS server lists.

```go
import "github.com/ruilisi/netutils/dns/servers"

// Available server lists:
servers.CNDNSServers           // Chinese DNS servers
servers.CNDNSServersSmall      // Small list of Chinese DNS servers
servers.SecurityDNSServers     // Security-focused DNS servers
servers.InternationalDNSServers // International public DNS servers
```

---

## ds

Generic data structures.

### Set

A generic Set implementation using Go generics. **Not concurrency-safe**.

```go
import "github.com/ruilisi/netutils/ds"

s := ds.NewSet[string]()
s.Add("apple")
s.Add("banana")
s.Has("apple")    // true
s.Remove("apple")
s.Values()        // []string{"banana"}
```

---

## http

HTTP utilities for raw requests and speed testing.

### BuildRawRequest

Builds a raw HTTP GET request as bytes.

```go
import nethttp "github.com/ruilisi/netutils/http"

reqBytes, err := nethttp.BuildRawRequest("http://example.com/file", map[string]string{
    "User-Agent": "MyApp/1.0",
})
```

### DownloadSpeedTCP

Measures download speed over an established TCP connection.

```go
import nethttp "github.com/ruilisi/netutils/http"

conn, _ := net.Dial("tcp", "example.com:80")
speed, err := nethttp.DownloadSpeedTCP(conn, reqBytes, 10*time.Second)
fmt.Printf("Speed: %.2f bytes/sec\n", speed)
```

### HostPortFromURL

Extracts host:port from a URL with default port handling.

```go
import nethttp "github.com/ruilisi/netutils/http"

hostPort, parsedURL, err := nethttp.HostPortFromURL("https://example.com:8080/path")
// hostPort = "example.com:8080"
```

### ReadCounterConn

Wraps a `net.Conn` to track bytes downloaded.

```go
import nethttp "github.com/ruilisi/netutils/http"

counter := &nethttp.ReadCounterConn{Conn: conn}
io.Copy(io.Discard, counter)
fmt.Printf("Downloaded: %d bytes\n", counter.Downloaded)
```

---

## ip

Comprehensive IP address handling, packet parsing, and manipulation.

### IP Version Detection

```go
import "github.com/ruilisi/netutils/ip"

ip.IsIPV6(&addr)              // Check net.IP
ip.IsIPNetV6(&cidr)           // Check net.IPNet
ip.IsIPNetStrV6("2001::/64")  // Check CIDR string (returns bool, error)
ip.IsIPNetStrV6B("2001::/64") // Check CIDR string (returns bool only)
```

### IP/CIDR Conversion

```go
import "github.com/ruilisi/netutils/ip"

// Convert IP to CIDR with full mask (/32 or /128)
ipNet := ip.IP2IPNetFullMask(netIP)
cidr, _ := ip.IPStrFullMask("192.168.1.1") // "192.168.1.1/32"

// Simple IPv4 to CIDR
ip.IP2CIDR("192.168.1.1") // "192.168.1.1/32"

// Parse CIDR strings
nets := ip.StrToIPNets("10.0.0.0/8,172.16.0.0/12", ",")
```

### Network Operations

```go
import "github.com/ruilisi/netutils/ip"

ip.IsDefaultIP(addr)           // Check if 0.0.0.0 or ::
ip.IsDefaultIPNet(ipNet)       // Check if 0.0.0.0/0 or ::/0
ip.EqualIPNet(a, b)            // Compare two IPNet objects
ip.IsIPStrInNet("10.0.0.5", ipNet) // Check if IP is in network
ip.GetBroadcastIPV4OfIPNet(ipNet)  // Get broadcast address
```

### Private Network Detection

```go
import "github.com/ruilisi/netutils/ip"

ip.IsPrivateIP(addr)       // RFC1918 (IPv4) / RFC4193 ULA (IPv6)
ip.IsPrivateNetwork(ipNet) // Check entire network
```

### Outbound Interface Detection

```go
import "github.com/ruilisi/netutils/ip"

iface, _ := ip.GetOutboundInterface() // Detect default route interface
ipStr, _ := ip.GetOutboundIP(iface)   // Get interface's IP
ipNet, _ := ip.GetOutboundIPNet(iface) // Get interface's IPNet
```

### Packet Parsing

```go
import "github.com/ruilisi/netutils/ip"

// Get IP version and protocol
ver := ip.GetIPVer(packet)           // 4, 6, or 0
ver, proto := ip.GetVerProto(packet) // Version and protocol number

// Extract addresses and ports
srcIP, dstIP := ip.GetIPs(packet)
srcPort, dstPort := ip.GetPorts(packet)

// Check protocol
if ip.IsUDP(packet) {
    payload, srcIP, srcPort, dstIP, dstPort, err := ip.ExtractUDPPayload(packet)
}

// Human-readable packet summary
summary := ip.SummarizePacket(packet)
// e.g., "IPv4 TCP 192.168.1.1:443 → 10.0.0.1:52341 [SYN] seq=123"
```

### UDP Packet Construction

```go
import "github.com/ruilisi/netutils/ip"

// Build IPv4 UDP packet
pkt := ip.BuildIPv4UDPPacket(localAddr, remoteAddr, payload)

// Build IPv6 UDP packet
pkt := ip.BuildIPv6UDPPacket(localAddr, remoteAddr, payload)
```

### DNS Packet Extraction

```go
import "github.com/ruilisi/netutils/ip"

qnames, ips, isQuery, dnsServer, ok := ip.ExtractDNSFromPacket(rawPacket)
// qnames: domain names from question section
// ips: resolved IPs from answer section (A/AAAA records)
// isQuery: true for queries, false for responses
// dnsServer: DNS server IP address
```

### DNS Packet Rewriting

```go
import "github.com/ruilisi/netutils/ip"

// Rewrite DNS packet destination to new server
ip.RewriteIPV4Dest(packet, "8.8.8.8") // Updates dest IP to 8.8.8.8:53
ip.RewriteIPV6Dest(packet, "2001:4860:4860::8888")
```

### Protocol Constants

157 IANA IP protocol numbers are available as constants:

```go
import "github.com/ruilisi/netutils/ip"

ip.ProtoICMP   // 1
ip.ProtoTCP    // 6
ip.ProtoUDP    // 17
ip.ProtoICMPv6 // 58
// ... and 153 more
```

---

## ping

ICMP ping and network reachability utilities.

### FastPing

Simple ICMP ping with timeout.

```go
import "github.com/ruilisi/netutils/ping"

err := ping.FastPing("8.8.8.8", 3*time.Second)
if err == nil {
    fmt.Println("Host is reachable")
}
```

### Ping

ICMP ping that returns round-trip time. Requires elevated privileges on most systems.

```go
import "github.com/ruilisi/netutils/ping"

rtt, err := ping.Ping(net.ParseIP("8.8.8.8"), 3*time.Second)
fmt.Printf("RTT: %v\n", rtt)
```

### PingCmd

Uses the system's `ping` command (no elevated privileges required).

```go
import "github.com/ruilisi/netutils/ping"

rtt, err := ping.PingCmd(net.ParseIP("8.8.8.8"), 3*time.Second)
```

### CheckReachability

Checks internet connectivity using DNS lookups and pings.

```go
import "github.com/ruilisi/netutils/ping"

if ping.CheckReachability() {
    fmt.Println("Internet is reachable")
}
```

---

## tcp

TCP connection utilities.

### SetWindow

Sets TCP send and receive buffer sizes.

```go
import "github.com/ruilisi/netutils/tcp"

conn, _ := net.Dial("tcp", "example.com:80")
tcp.SetWindow(conn, 65536, 65536) // 64KB buffers
```

---

## tun

TUN device support for packet tunneling. Platform-specific implementations for Windows, Linux, and macOS.

---

## util

General utilities.

### DumpHex

Prints a hex dump of bytes (similar to `hexdump -C`).

```go
import "github.com/ruilisi/netutils/util"

util.DumpHex(data)
// Output:
// 00000000  48 65 6c 6c 6f 20 57 6f  72 6c 64 21              |Hello World!|
```

### HexToBytes

Converts a space-separated hex string to bytes.

```go
import "github.com/ruilisi/netutils/util"

data, err := util.HexToBytes("48 65 6c 6c 6f")
// data = []byte("Hello")
```

---

## Development

### Prerequisites

- Go 1.23+
- golangci-lint (for linting)

### Makefile Targets

```bash
# Build
make build          # Build the project
make install        # Install binary to $GOBIN
make run            # Run the app
make clean          # Remove build files and generated files

# Test
make test           # Run tests
make test-v         # Run tests (verbose)
make test-race      # Run tests with race detector
make test-short     # Run short tests only
make test-cover     # Run tests with coverage
make test-cover-html # Generate HTML coverage report

# Benchmark
make bench          # Run all benchmarks
make bench-mem      # Run benchmarks with memory stats
make bench-count    # Run benchmarks 5x for stable results
make bench-save     # Save benchmark results to bench.txt
make bench-cpu      # Run benchmarks with CPU profile
make bench-mem-profile # Run benchmarks with memory profile

# Code Quality
make fmt            # Format code
make vet            # Run go vet
make lint           # Run linter (needs golangci-lint)
make check          # Run fmt, vet, lint, and test

# Dependencies
make tidy           # Clean up go.mod/go.sum
make deps           # Download dependencies
```

### Running Tests

```bash
# Run all tests
go test ./...

# Run tests for a specific package
go test ./ip/...

# Run with verbose output
go test -v ./...

# Run benchmarks
go test -bench=. -benchmem ./...
```

## License

MIT License - see [LICENSE](LICENSE) for details.
