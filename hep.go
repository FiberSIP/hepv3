package hep

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
	"time"
)

var HEPCookie1 = []byte("HEP3")
var HEPCookie2 = []byte("EEP3")

const HepChunkHeaderSize = 6

const (
	IPProtocolFamily  = 0x01
	IPProtocolID      = 0x02
	IP4SrcAddress     = 0x03
	IP4DstnAddress    = 0x04
	IP6SrcAddress     = 0x05
	IP6DstAddress     = 0x06
	SrcPort           = 0x07
	DstPort           = 0x08
	Timestamp         = 0x09
	TimestampMicro    = 0x0a
	ProtocolType      = 0x0b
	CaptureAgentID    = 0x0c
	KeepAliveTimer    = 0x0d
	AuthenticationKey = 0x0e
	CapturedPaylod    = 0x0f
	CompressedPayload = 0x10
	CorrID            = 0x11
	VlanID            = 0x12
	CaptureAgentName  = 0x13
	SrcMac            = 0x14
	DstMac            = 0x15
	EthernetType      = 0x16
	TCPFlag           = 0x17
	IPTos             = 0x18
	Reserved          = 0x1F
	MosValue          = 0x20
	RFactor           = 0x21
	GEOLocation       = 0x22
	Jitter            = 0x23
	TmType            = 0x24
	JSONKeys          = 0x25
	TagValues         = 0x26
	Tags              = 0x27
	EventType         = 0x28
	GroupID           = 0x29
)

var ChunkLenChecker = [...]int{
	IPProtocolFamily: HepChunkHeaderSize + 1,
	IPProtocolID:     HepChunkHeaderSize + 1,
	IP4SrcAddress:    HepChunkHeaderSize + 4,
	IP4DstnAddress:   HepChunkHeaderSize + 4,
	IP6SrcAddress:    HepChunkHeaderSize + 16,
	IP6DstAddress:    HepChunkHeaderSize + 16,
	SrcPort:          HepChunkHeaderSize + 2,
	DstPort:          HepChunkHeaderSize + 2,
	Timestamp:        HepChunkHeaderSize + 4,
	TimestampMicro:   HepChunkHeaderSize + 4,
	ProtocolType:     HepChunkHeaderSize + 1,
	CaptureAgentID:   HepChunkHeaderSize + 4,
	KeepAliveTimer:   HepChunkHeaderSize + 2,
	VlanID:           HepChunkHeaderSize + 2,
	SrcMac:           HepChunkHeaderSize + 8,
	DstMac:           HepChunkHeaderSize + 8,
	EthernetType:     HepChunkHeaderSize + 2,
	TCPFlag:          HepChunkHeaderSize + 1,
	IPTos:            HepChunkHeaderSize + 1,
	MosValue:         HepChunkHeaderSize + 2,
	RFactor:          HepChunkHeaderSize + 2,
	Jitter:           HepChunkHeaderSize + 4,
	Tags:             HepChunkHeaderSize + 2,
	EventType:        HepChunkHeaderSize + 2,
}

type HepPkt struct {
	IPProtocolFamily  uint8
	IPProtocolID      uint8
	IP4SrcAddress     string
	IP4DstAddress     string
	IP6SrcAddress     string
	IP6DstAddress     string
	SrcPort           uint16
	DstPort           uint16
	Timestamp         uint32
	TimestampMicro    uint32
	ProtocolType      uint8
	CaptureAgentID    uint32
	KeepAliveTimer    uint16
	AuthenticationKey string
	CapturedPaylod    []byte
	CompressedPayload []byte
	CorrID            string
	VlanID            uint16
	CaptureAgentName  string
	SrcMac            uint64
	DstMac            uint64
	EthernetType      uint16
	TCPFlags          uint8
	IPTos             uint8
	MosValue          uint16
	RFactor           uint16
	GEOLocation       string
	Jitter            uint32
	TmType            string
	JSONKeys          string
	TagValues         string
	Tags              uint16
	EventType         uint16
	GroupID           string
}

// NewHepMsg returns a parsed message object. Takes a byte slice.
func NewHepMsg(packet []byte) (*HepPkt, error) {
	newHepMsg := &HepPkt{}
	err := newHepMsg.parse(packet)
	if err != nil {
		return nil, err
	}
	return newHepMsg, nil
}

func (h *HepPkt) parse(udpPacket []byte) error {
	if len(udpPacket) < HepChunkHeaderSize {
		return fmt.Errorf("packet too short: %d", len(udpPacket))
	}

	cookie := udpPacket[0:4]
	totalLen := binary.BigEndian.Uint16(udpPacket[4:6])

	if int(totalLen) != len(udpPacket) {
		return fmt.Errorf("packet length mismatch。expected %d , but got %d", totalLen, len(udpPacket))
	}

	if bytes.Equal(cookie, HEPCookie1) || bytes.Equal(cookie, HEPCookie2) {
		return h.parseHep3(udpPacket)
	}

	return fmt.Errorf("invalid hep cookie: %s, expect %s or %s", cookie, HEPCookie1, HEPCookie2)

}

func (h *HepPkt) parseHep3(udpPacket []byte) error {
	currentByte := uint16(6)

	for int(currentByte) < cap(udpPacket) {
		hepChunk := udpPacket[currentByte:]

		if len(hepChunk) <= HepChunkHeaderSize {
			return fmt.Errorf("chunk length too small: %d", len(hepChunk))
		}

		chunkType := binary.BigEndian.Uint16(hepChunk[2:4])
		chunkLength := binary.BigEndian.Uint16(hepChunk[4:6])

		if chunkLength < HepChunkHeaderSize {
			return fmt.Errorf("invalid chunk length: %d", chunkLength)
		}

		if int(chunkLength) > cap(hepChunk) {
			return fmt.Errorf("invalid chunk length: %d  cap: %d", chunkLength, cap(hepChunk))
		}

		if chunkType > GroupID {
			return fmt.Errorf("invalid chunk type: %d", chunkType)
		}

		if int(chunkType) < len(ChunkLenChecker) && ChunkLenChecker[chunkType] > 0 && int(chunkLength) != ChunkLenChecker[chunkType] {
			return fmt.Errorf("invalid chunk length for type %d: %d != %d", chunkType, chunkLength, ChunkLenChecker[chunkType])
		}

		currentByte += chunkLength
		chunkBody := hepChunk[6:chunkLength]

		switch chunkType {
		case IPProtocolFamily:
			h.IPProtocolFamily = chunkBody[0]
		case IPProtocolID:
			h.IPProtocolID = chunkBody[0]
		case IP4SrcAddress:
			h.IP4SrcAddress = net.IP(chunkBody).String()
		case IP4DstnAddress:
			h.IP4DstAddress = net.IP(chunkBody).String()
		case IP6SrcAddress:
			h.IP6SrcAddress = net.IP(chunkBody).String()
		case IP6DstAddress:
			h.IP4DstAddress = net.IP(chunkBody).String()
		case SrcPort:
			h.SrcPort = binary.BigEndian.Uint16(chunkBody)
		case DstPort:
			h.DstPort = binary.BigEndian.Uint16(chunkBody)
		case Timestamp:
			h.Timestamp = binary.BigEndian.Uint32(chunkBody)
		case TimestampMicro:
			h.TimestampMicro = binary.BigEndian.Uint32(chunkBody)
		case ProtocolType:
			h.ProtocolType = chunkBody[0]
		case CaptureAgentID:
			h.CaptureAgentID = binary.BigEndian.Uint32(chunkBody)
		case KeepAliveTimer:
		case AuthenticationKey:
		case CapturedPaylod:
			h.PacketPayload = chunkBody
		case CompressedPayload:
		case CorrID:
			h.InternalCorrelationID = string(chunkBody)
		case VlanID:
		case CaptureAgentName:
		case SrcMac:
		case DstMac:
		case EthernetType:
		case TCPFlag:
		case IPTos:
		case MosValue:
		case RFactor:
		case GEOLocation:
		case Jitter:
		case TmType:
		case JSONKeys:
		case TagValues:
		case Tags:
		case EventType:
		case GroupID:
		default:
		}
	}

	h.Ts = time.Unix(int64(h.Timestamp), int64(h.TimestampMicro)*1000)
	h.NanoTs = h.Ts.UnixNano()

	return nil
}
