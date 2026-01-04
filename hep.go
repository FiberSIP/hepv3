package hepv3

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net"
)

var HEPCookie1 = []byte("HEP3")
var HEPCookie2 = []byte("EEP3")

const HepChunkHeaderSize = 6

const (
	IPv4 = 0x02
	IPv6 = 0x0a
)

const (
	TCP = 0x06
	UDP = 0x11
	TLS = 0x16
	ESP = 0x32
)

const (
	IPProtocolFamily  = 0x01 // (0x02=IPv4, 0x0a=IPv6)
	IPProtocolID      = 0x02 // (0x06=TCP, 0x11=UDP, 0x16=TLS, 0x32=ESP)
	IP4SrcAddress     = 0x03
	IP4DstAddress     = 0x04
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
	CapturedPayload   = 0x0f
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

var ChunkLenChecker = [...]uint16{
	IPProtocolFamily: HepChunkHeaderSize + 1,
	IPProtocolID:     HepChunkHeaderSize + 1,
	IP4SrcAddress:    HepChunkHeaderSize + 4,
	IP4DstAddress:    HepChunkHeaderSize + 4,
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
	TotalLen          uint16
	HeaderID          []byte
	IPProtocolFamily  uint8
	IPProtocolID      uint8
	IP4SrcAddress     net.IP
	IP4DstAddress     net.IP
	IP6SrcAddress     net.IP
	IP6DstAddress     net.IP
	SrcPort           uint16
	DstPort           uint16
	Timestamp         uint32
	TimestampMicro    uint32
	ProtocolType      uint8
	CaptureAgentID    uint32
	KeepAliveTimer    uint16
	AuthenticationKey string
	CapturedPayload   []byte
	CompressedPayload []byte
	CorrID            string
	VlanID            uint16
	CaptureAgentName  string
	SrcMac            uint64
	DstMac            uint64
	EthernetType      uint16
	TCPFlag           uint8
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

func New(packet []byte) (*HepPkt, error) {
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

	h.HeaderID = udpPacket[0:4]
	h.TotalLen = binary.BigEndian.Uint16(udpPacket[4:6])

	if int(h.TotalLen) != len(udpPacket) {
		return fmt.Errorf("packet length mismatch。expected %d , but got %d", h.TotalLen, len(udpPacket))
	}

	if bytes.Equal(h.HeaderID, HEPCookie1) || bytes.Equal(h.HeaderID, HEPCookie2) {
		return h.parseHep3(udpPacket)
	}

	return fmt.Errorf("invalid hep HeaderID: %s, expect %s or %s", h.HeaderID, HEPCookie1, HEPCookie2)

}

func (h *HepPkt) parseHep3(udpPacket []byte) error {
	currentByte := uint16(6)

	for int(currentByte) < len(udpPacket) {
		hepChunk := udpPacket[currentByte:]

		if len(hepChunk) <= HepChunkHeaderSize {
			return fmt.Errorf("chunk length too small: %d, currentByte: %d, total: %d", len(hepChunk), currentByte, cap(udpPacket))
		}

		chunkType := binary.BigEndian.Uint16(hepChunk[2:4])
		chunkLength := binary.BigEndian.Uint16(hepChunk[4:6])

		if chunkLength < HepChunkHeaderSize {
			return fmt.Errorf("invalid chunk length: %d", chunkLength)
		}

		if int(chunkLength) > len(hepChunk) {
			return fmt.Errorf("invalid chunk length: %d  len: %d", chunkLength, len(hepChunk))
		}

		if chunkType > GroupID {
			return fmt.Errorf("invalid chunk type: %d", chunkType)
		}

		if int(chunkType) < len(ChunkLenChecker) && ChunkLenChecker[chunkType] > 0 && chunkLength != ChunkLenChecker[chunkType] {
			return fmt.Errorf("invalid chunk length for type %d: %d != %d", chunkType, chunkLength, ChunkLenChecker[chunkType])
		}

		currentByte += chunkLength
		chunkBody := hepChunk[6:chunkLength]

		switch chunkType {
		case IPProtocolFamily:
			// (0x02=IPv4, 0x0a=IPv6)
			h.IPProtocolFamily = chunkBody[0]
		case IPProtocolID:
			// (0x06=TCP, 0x11=UDP, 0x16=TLS, 0x32=ESP)
			h.IPProtocolID = chunkBody[0]
		case IP4SrcAddress:
			h.IP4SrcAddress = net.IP(chunkBody).To4()
		case IP4DstAddress:
			h.IP4DstAddress = net.IP(chunkBody).To4()
		case IP6SrcAddress:
			h.IP6SrcAddress = net.IP(chunkBody)
		case IP6DstAddress:
			h.IP6DstAddress = net.IP(chunkBody)
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
			h.KeepAliveTimer = binary.BigEndian.Uint16(chunkBody)
		case AuthenticationKey:
			h.AuthenticationKey = string(chunkBody)
		case CapturedPayload:
			h.CapturedPayload = chunkBody
		case CompressedPayload:
			h.CompressedPayload = chunkBody
		case CorrID:
			h.CorrID = string(chunkBody)
		case VlanID:
			h.VlanID = binary.BigEndian.Uint16(chunkBody)
		case CaptureAgentName:
			h.CaptureAgentName = string(chunkBody)
		case SrcMac:
			h.SrcMac = binary.BigEndian.Uint64(chunkBody)
		case DstMac:
			h.DstMac = binary.BigEndian.Uint64(chunkBody)
		case EthernetType:
			h.EthernetType = binary.BigEndian.Uint16(chunkBody)
		case TCPFlag:
			h.TCPFlag = chunkBody[0]
		case IPTos:
			h.IPTos = chunkBody[0]
		case MosValue:
			h.MosValue = binary.BigEndian.Uint16(chunkBody)
		case RFactor:
			h.RFactor = binary.BigEndian.Uint16(chunkBody)
		case GEOLocation:
			h.GEOLocation = string(chunkBody)
		case Jitter:
			h.Jitter = binary.BigEndian.Uint32(chunkBody)
		case TmType:
			h.TmType = string(chunkBody)
		case JSONKeys:
			h.JSONKeys = string(chunkBody)
		case TagValues:
			h.TagValues = string(chunkBody)
		case Tags:
			h.Tags = binary.BigEndian.Uint16(chunkBody)
		case EventType:
			h.EventType = binary.BigEndian.Uint16(chunkBody)
		case GroupID:
			h.GroupID = string(chunkBody)
		default:
		}
	}

	return nil
}

func (m *HepPkt) ToBytes(initBufSize int) []byte {
	buf := make([]byte, 0, initBufSize)
	buf = append(buf, 'H', 'E', 'P', '3', 0, 0)

	buf = appendChunkU8(buf, IPProtocolFamily, m.IPProtocolFamily)
	buf = appendChunkU8(buf, IPProtocolID, m.IPProtocolID)

	if m.IPProtocolFamily == IPv4 {
		buf = appendChunkIP4(buf, IP4SrcAddress, m.IP4SrcAddress)
		buf = appendChunkIP4(buf, IP4DstAddress, m.IP4DstAddress)
	} else {
		buf = appendChunkIP6(buf, IP6SrcAddress, m.IP6SrcAddress)
		buf = appendChunkIP6(buf, IP6DstAddress, m.IP6DstAddress)
	}

	buf = appendChunkU16(buf, SrcPort, m.SrcPort)
	buf = appendChunkU16(buf, DstPort, m.DstPort)

	buf = appendChunkU32(buf, Timestamp, m.Timestamp)
	buf = appendChunkU32(buf, TimestampMicro, m.TimestampMicro)

	buf = appendChunkU8(buf, ProtocolType, m.ProtocolType)
	buf = appendChunkU32(buf, CaptureAgentID, m.CaptureAgentID)
	buf = appendChunkU16(buf, KeepAliveTimer, m.KeepAliveTimer)

	buf = appendChunkString(buf, AuthenticationKey, m.AuthenticationKey)
	buf = appendChunkBytes(buf, CapturedPayload, m.CapturedPayload)
	buf = appendChunkBytes(buf, CompressedPayload, m.CompressedPayload)
	buf = appendChunkString(buf, CorrID, m.CorrID)

	buf = appendChunkU16(buf, VlanID, m.VlanID)
	buf = appendChunkString(buf, CaptureAgentName, m.CaptureAgentName)

	buf = appendChunkU64(buf, SrcMac, m.SrcMac)
	buf = appendChunkU64(buf, DstMac, m.DstMac)
	buf = appendChunkU16(buf, EthernetType, m.EthernetType)
	buf = appendChunkU8(buf, TCPFlag, m.TCPFlag)
	buf = appendChunkU8(buf, IPTos, m.IPTos)
	buf = appendChunkU16(buf, MosValue, m.MosValue)
	buf = appendChunkU16(buf, RFactor, m.RFactor)

	buf = appendChunkString(buf, GEOLocation, m.GEOLocation)
	buf = appendChunkU32(buf, Jitter, m.Jitter)
	buf = appendChunkString(buf, TmType, m.TmType)
	buf = appendChunkString(buf, TagValues, m.TagValues)
	buf = appendChunkU16(buf, Tags, m.Tags)
	buf = appendChunkU16(buf, EventType, m.EventType)
	buf = appendChunkString(buf, GroupID, m.GroupID)

	binary.BigEndian.PutUint16(buf[4:6], uint16(len(buf)))

	return buf
}
