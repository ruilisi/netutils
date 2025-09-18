# ReservedIP Package

This package provides efficient checking of reserved IP address ranges for both IPv4 and IPv6 addresses. It supports two implementations based on build configuration:

1. **Pure Go implementation** (default): Used on non-Windows platforms or when cgo is disabled
2. **CGO-accelerated C++ implementation**: Used on Windows when cgo is enabled

## API

```go
package reservedip

import "net"

// IsReservedIP checks if the given IP address is in a reserved range
func IsReservedIP(ip net.IP) bool
```

## Reserved IP Ranges

The package checks for reserved IP ranges that are **not already covered** by the standard library methods:
- `ip.IsPrivate()`
- `ip.IsLoopback()` 
- `ip.IsLinkLocalUnicast()`

### IPv4 Reserved Ranges (Reduced Set)
- `0.0.0.0/8` - Current network (default route)
- `100.64.0.0/10` - Shared address space (carrier-grade NAT)
- `192.0.0.0/29` - IPv4 special purpose
- `192.0.2.0/24` - TEST-NET-1 (documentation examples)
- `192.88.99.0/24` - 6to4 relay anycast
- `198.18.0.0/15` - Network benchmarking
- `198.51.100.0/24` - TEST-NET-2 (documentation examples)
- `203.0.113.0/24` - TEST-NET-3 (documentation examples)
- `224.0.0.0/3` - Multicast addresses

### IPv6 Reserved Ranges (Reduced Set)
- `::/128` - IPv6 unspecified address
- `::ffff:0:0/96` - IPv4-mapped addresses
- `100::/64` - Discard prefix
- `2001::/32` - Teredo tunneling
- `2001:10::/28` - ORCHID (old)
- `2001:20::/28` - ORCHIDv2
- `2001:db8::/32` - Documentation example addresses
- `ff00::/8` - IPv6 multicast addresses

## Build Instructions

### Default Build (Pure Go)
```bash
go build ./...
```

### Windows with CGO (C++ Acceleration)
Requires MinGW-w64 or MSYS2 toolchain installed:

```bash
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 go build ./...
```

### Cross-compilation Examples
```bash
# Windows AMD64 with cgo
CGO_ENABLED=1 GOOS=windows GOARCH=amd64 CC=x86_64-w64-mingw32-gcc go build ./...

# Windows 386 with cgo  
CGO_ENABLED=1 GOOS=windows GOARCH=386 CC=i686-w64-mingw32-gcc go build ./...

# Force pure Go on Windows (disable cgo)
CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build ./...
```

## Implementation Details

### Pure Go Implementation (`reservedip_pure.go`)
- Uses `net.IPNet.Contains()` for range checking
- Linear scan through predefined CIDR ranges
- Thread-safe with `sync.Once` initialization

### CGO C++ Implementation (`reservedip_cgo.go`, `reservedip.cpp`)
- Binary search for IPv4 ranges (O(log n) complexity)
- Linear scan for IPv6 prefixes (small list, cache-friendly)
- Optimized C++ implementation with minimal overhead
- Standard library checks performed first in Go before C++ calls

## Performance

The C++ implementation provides performance benefits for high-frequency IP checking:
- IPv4: Binary search through sorted ranges
- IPv6: Efficient prefix matching with bit operations
- Reduced range set focuses on non-stdlib-covered ranges only

## Build Tags

- `//go:build !windows || !cgo` - Pure Go implementation
- `//go:build windows && cgo` - CGO C++ implementation

## Dependencies

- **Pure Go**: Only standard library
- **CGO**: Requires C++ compiler (MinGW-w64 or MSYS2 on Windows)