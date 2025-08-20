# netutils

## Overview
A network utility toolkit written in Go, focused on solving various network-related challenges. It provides efficient network diagnostics, connection testing, protocol analysis, and other functionalities to help developers and operations personnel quickly locate and resolve network issues.

## Tool Introduction

### device
Tools related to device information.

#### `GetUniqId`
Generates a unique identifier for the device. Supports Windows, macOS, and Linux/Darwin operating systems.

**Location:** `device/uniq_id.go`
**Signature:** `func GetUniqId() (string, error)`

---

### dns
Tools related to DNS.

#### `LookupAddrLocalDNS`
Finds the domain name(s) corresponding to an IP address in the local DNS resolver.

**Location:** `dns/dns.go`
**Signature:** `func LookupAddrLocalDNS(addr string) ([]string, error)`

---

### ds (Data Structure)
Data structure utilities.

#### `Set`
A generic Set structure implemented using Go generics. Contains `Add`, `Remove`, `Has`, `Values` methods. **Not concurrency-safe**.

**Location:** `ds/set.go`

---

### http
HTTP-related utilities.

#### `ReadCounterConn`
An HTTP download traffic counter, implementing the decorator pattern by wrapping a `net.Conn` to count bytes read.

**Location:** `http/http.go`
**Type:** `type ReadCounterConn struct { ... }`

#### `BuildRawRequest`
Raw HTTP GET request builder. Uses port 80 by default.

**Location:** `http/http.go`
**Signature:** `func BuildRawRequest(url string, headers map[string]string) ([]byte, error)`

#### `DownloadSpeedTCP`
TCP download speed test. Measures the download speed over an established TCP connection by sending a request and measuring the response throughput over a specified duration.

**Location:** `http/http.go`
**Signature:** `func DownloadSpeedTCP(conn net.Conn, reqBytes []byte, duration time.Duration) (float64, error)`

#### `HostPortFromURL`
URL parsing utility. Parses a string like `https://example.com:8080/path?key=value#frag` into a `url.URL` object and extracts the host:port part.

**Location:** `http/http.go`
**Signature:** `func HostPortFromURL(rawURL string) (string, *url.URL, error)`

---

### ip
Tools related to IP addresses.

#### `IsIPV6` / `IsIPNetV6` / `IsIPNetStrV6B` / `IsIPNetStrV6`
IPv6 detector. Supports `net.IP`, `net.IPNet`, and `String` inputs in CIDR or standard format to determine if the address is IPv6.

**Location:** `ip/ip.go`
**Signatures:**
- `func IsIPV6(ip net.IP) bool`
- `func IsIPNetV6(cidr *net.IPNet) bool`
- `func IsIPNetStrV6B(ipNetStr string) bool` // Boolean result, may panic on error
- `func IsIPNetStrV6(ipNetStr string) (bool, error)` // Explicit error handling

#### `IP2IPNetFullMask` / `IPStrFullMask`
Full mask (host mask, `/32` for IPv4, `/128` for IPv6) generator. Supports IP addresses in both `net.IP` and `string` formats.

**Location:** `ip/ip.go`
**Signatures:**
- `func IP2IPNetFullMask(ip net.IP) *net.IPNet`
- `func IPStrFullMask(ipStr string) (string, error)`

#### `IsDefaultIP`
Default address checker. Checks if an IP address is the unspecified address (e.g., `0.0.0.0` for IPv4, `::` for IPv6).

**Location:** `ip/ip.go`
**Signature:** `func IsDefaultIP(ip net.IP) bool`

#### `IP2CIDR`
Converts an IPv4 string to a CIDR format string by automatically appending "/32". **Does not support IPv6**.

**Location:** `ip/ip.go`
**Signature:** `func IP2CIDR(ip string) string`

#### `GetBroadcastIPV4OfIPNet`
Gets the broadcast address for an IPv4 network.

**Location:** `ip/ip.go`
**Signature:** `func GetBroadcastIPV4OfIPNet(ipnet *net.IPNet) (net.IP, error)`

#### `EqualIPNet`
Checks if two `net.IPNet` objects represent the same network address and mask.

**Location:** `ip/ip.go`
**Signature:** `func EqualIPNet(a, b *net.IPNet) bool`

#### `IsIPStrInNet`
Checks if a given IP address (string) is within a specified `net.IPNet`.

**Location:** `ip/ip.go`
**Signature:** `func IsIPStrInNet(ipStr string, ipNet *net.IPNet) (bool, error)`

#### `GetOutboundInterface`
Gets the network interface likely used for outbound traffic to a default route (e.g., `8.8.8.8:53`).

**Location:** `ip/outbound.go`
**Signature:** `func GetOutboundInterface() (*net.Interface, error)`

#### `GetOutboundIP`
Gets the first IP address of the specified outbound interface.

**Location:** `ip/outbound.go`
**Signature:** `func GetOutboundIP(iface *net.Interface) (string, error)`

#### `GetOutboundIPNet`
Gets the first IP network (`net.IPNet`) of the specified outbound interface.

**Location:** `ip/outbound.go`
**Signature:** `func GetOutboundIPNet(iface *net.Interface) (*net.IPNet, error)`

#### `IsPrivateNetwork` / `IsPrivateIP`
Determines if an IP network or address is private according to the RFC1918 (IPv4) and RFC4193 (IPv6 ULA) standards.

**Location:** `ip/private.go`
**Signatures:**
- `func IsPrivateNetwork(ipnet *net.IPNet) bool`
- `func IsPrivateIP(ip net.IP) bool`

---

### ping
Tools for probing and reachability.

#### `FastPing`
Sends an ICMP ping (Echo Request) to a specified IP address and waits for a reply (Echo Reply) within a given timeout. Returns `nil` on success, or an error on failure/timeout.

**Location:** `ping/ping.go`
**Signature:** `func FastPing(addr string, timeout time.Duration) error`

#### `PingCmd`
Sends a ping to a specified IP address using the system's `ping` command and waits for a reply within a given timeout. Returns the round-trip time on success. Cross-platform compatibility may vary.

**Location:** `ping/ping.go`
**Signature:** `func PingCmd(host string, timeout time.Duration, count int) (time.Duration, error)` // *Signature inferred*

#### `CheckReachability`
Checks device internet connectivity. Tests reachability using DNS lookups (e.g., for `google.com`) and/or pinging multiple well-known targets. Returns `true` if any check succeeds.

**Location:** `ping/reachability.go`
**Signature:** `func CheckReachability() bool`