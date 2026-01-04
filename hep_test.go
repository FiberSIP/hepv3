package hepv3

import (
	"net"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestParseOk001(t *testing.T) {
	// TODO: write test
	h1 := HepPkt{
		IPProtocolFamily:  0x02,
		IPProtocolID:      0x11,
		IP4SrcAddress:     net.IPv4(192, 168, 0, 1).To4(),
		IP4DstAddress:     net.IPv4(192, 168, 0, 1).To4(),
		SrcPort:           12345,
		DstPort:           5060,
		Timestamp:         199329939,
		CapturedPayload:   []byte("head\r\n\r\nbody"),
		AuthenticationKey: "this is a key",
		TmType:            "REGISTER",
	}

	buf := h1.ToBytes(512)

	h2, err := New(buf)

	assert.Nil(t, err)
	assert.Equal(t, h1.IPProtocolFamily, h2.IPProtocolFamily)
	assert.Equal(t, h1.IPProtocolID, h2.IPProtocolID)
	assert.Equal(t, h1.IP4SrcAddress, h2.IP4SrcAddress)
	assert.Equal(t, h1.IP4DstAddress, h2.IP4DstAddress)
	assert.Equal(t, h1.SrcPort, h2.SrcPort)
	assert.Equal(t, h1.DstPort, h2.DstPort)
	assert.Equal(t, h1.Timestamp, h2.Timestamp)
	assert.Equal(t, h1.CapturedPayload, h2.CapturedPayload)
	assert.Equal(t, h1.AuthenticationKey, h2.AuthenticationKey)
	assert.Equal(t, h1.TmType, h2.TmType)
}
