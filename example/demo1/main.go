package main

import (
	"fmt"
	"hepv3"
	"net"
	"os"
)

func main() {
	h1 := hepv3.HepPkt{
		IPProtocolFamily:  0x02,
		IPProtocolID:      0x11,
		IP4SrcAddress:     net.IPv4(192, 168, 0, 1),
		IP4DstAddress:     net.IPv4(192, 168, 0, 1),
		SrcPort:           12345,
		DstPort:           5060,
		Timestamp:         199329939,
		CapturedPayload:   []byte("head\r\n\r\nbody"),
		AuthenticationKey: "this is a key",
		TmType:            "REGISTER",
	}

	buf := h1.ToBytes(512)

	fmt.Printf("%q\n", buf)
	fmt.Printf("%d\n", len(buf))

	err := os.WriteFile("abc.bin", buf, 0644)

	if err != nil {
		fmt.Println(err)
		return
	}
}
