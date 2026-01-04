# hepv3
hepv3

# API

## Bytes to Hep

```go
hep, err := hepv3.New(buf[:])

if err != nil {
	fmt.Println(err)
	return
}

fmt.Printf("%#v", hep)
```

## Hep To bytes

```go
h1 := hepv3.HepPkt{
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
```


## Generic chunk types

## IPProtocolFamily (0x01)

ID | protocol family
---|---
0x02 | IPv4
0x0a | IPv6

## IPProtocolID (0x02)

ID | protocol
---|---
0x06 | TCP
0x11 | UDP
0x16 | TLS
0x32 | ESP


## ProtocolType (0x0b)

chunk protocol ID | assigned vendor
----------------- | --------------
0x00 | reserved
0x01 | SIP
0x02 | XMPP
0x03 | SDP
0x04 | RTP
0x05 | RTCP JSON
0x06 | MGCP
0x07 | MEGACO (H.248)
0x08 | M2UA (SS7/SIGTRAN)
0x09 | M3UA (SS7/SIGTRAN)
0x0a | IAX
0x0b | H3222
0x0c | H321
0x0d | M2PA
0x22 | MOS full report [JSON]
0x23 | MOS short report. Please use mos chunk 0x20 [JSON]
0x32 | SIP JSON
0x33 | RESERVED
0x34 | RESERVED
0x35 | DNS JSON
0x36 | M3UA JSON (ISUP)
0x37 | RTSP (JSON)
0x38 | DIAMETER (JSON)
0x39 | GSM MAP (JSON)
0x3a | RTCP PION
0x3b | RESERVED
0x3c | CDR (can be for call and registration transaction)
0x3d | Verto (JSON event/signaling protocol)

## Vendor chunk types

chunk vendor ID | assigned vendor
--------------- | ----------------
0x0000 | No specific vendor, generic chunk types, see above
0x0001 | FreeSWITCH (www.freeswitch.org)
0x0002 | Kamailio/SER (www.kamailio.org)
0x0003 | OpenSIPS (www.opensips.org)
0x0004 | Asterisk (www.asterisk.org)
0x0005 | Homer Project (http://www.sipcapture.org)
0x0006 | SipXecs (www.sipfoundry.org/)
0x0007 | Yeti Switch (https://yeti-switch.org/)
0x0008 | Genesys (https://www.genesys.com/)

## EventType (0x028)
chunk event type | Event name
--- | ---
0x000 | reserved
0x001 | Recording
0x002 | Recording LI