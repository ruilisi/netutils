package dns

import (
	"testing"

	"github.com/ruilisi/netutils/util"
	"github.com/stretchr/testify/assert"
)

func TestInvalidDNSPacket(t *testing.T) {
	// below packet is used for network test of Switch
	pkt, _ := util.HexToBytes("00 00 00 67 00 00 00 00 00 00 00 00 00 00 00 00")

	assert.False(t, IsLikelyDNSPacket(pkt), "Packet should be identified as invalid DNS")
}
