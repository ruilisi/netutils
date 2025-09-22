package dns

import (
	"encoding/binary"
)

// IsLikelyDNSPacket checks if a raw UDP payload is likely a DNS packet
func IsLikelyDNSPacket(pkt []byte) bool {
	// Must be at least 12 bytes (DNS header)
	if len(pkt) < 12 {
		return false
	}

	// Extract header fields
	flags := binary.BigEndian.Uint16(pkt[2:4])
	qdCount := binary.BigEndian.Uint16(pkt[4:6])

	// QR bit: 0=query, 1=response
	qr := (flags >> 15) & 0x1

	// Common checks:
	// - must be a query or response (QR = 0 or 1)
	// - must have at least one question (optional, depends on use case)
	if qr != 0 && qr != 1 {
		return false
	}
	if qdCount == 0 {
		return false
	}

	return true
}
