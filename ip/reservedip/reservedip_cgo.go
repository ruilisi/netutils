//go:build (windows || linux) && cgo

package reservedip

/*
#include "reservedip.h"
*/
import "C"
import (
	"encoding/binary"
	"net"
	"unsafe"
)

// IsReservedIP checks if IP is in reserved address ranges (supports IPv4 and IPv6)
// This implementation uses cgo to call optimized C++ functions after performing
// standard library checks first.
func IsReservedIP(ip net.IP) bool {
	if ip == nil {
		return false
	}

	// Check IsPrivate, IsLoopback, IsLinkLocalUnicast first (stdlib optimized methods)
	if ip.IsPrivate() || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
		return true
	}

	// Check IPv4 reserved addresses using C++ implementation
	if ipv4 := ip.To4(); ipv4 != nil {
		// Convert IPv4 to big-endian uint32
		ipBE := binary.BigEndian.Uint32(ipv4)
		result := C.IsReservedIPv4(C.uint32_t(ipBE))
		return result != 0
	}

	// Check IPv6 reserved addresses using C++ implementation
	if ipv6 := ip.To16(); ipv6 != nil {
		// Pass pointer to 16-byte slice to C++ function
		result := C.IsReservedIPv6((*C.uint8_t)(unsafe.Pointer(&ipv6[0])))
		return result != 0
	}

	return false
}
