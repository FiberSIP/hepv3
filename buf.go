package hepv3

import "net"

func appendChunkHeader(buf []byte, t uint16, dataLen int) []byte {
	l := dataLen + 6
	return append(buf,
		0, 0,
		byte(t>>8), byte(t),
		byte(l>>8), byte(l),
	)
}

func appendChunkU8(buf []byte, t uint16, v uint8) []byte {
	if v == 0 {
		return buf
	}
	buf = appendChunkHeader(buf, t, 1)
	return append(buf, v)
}

func appendChunkU16(buf []byte, t uint16, v uint16) []byte {
	if v == 0 {
		return buf
	}
	buf = appendChunkHeader(buf, t, 2)
	return append(buf, byte(v>>8), byte(v))
}

func appendChunkU32(buf []byte, t uint16, v uint32) []byte {
	if v == 0 {
		return buf
	}
	buf = appendChunkHeader(buf, t, 4)
	return append(buf,
		byte(v>>24), byte(v>>16),
		byte(v>>8), byte(v),
	)
}

func appendChunkU64(buf []byte, t uint16, v uint64) []byte {
	if v == 0 {
		return buf
	}
	buf = appendChunkHeader(buf, t, 8)
	return append(buf,
		byte(v>>56), byte(v>>48),
		byte(v>>40), byte(v>>32),
		byte(v>>24), byte(v>>16),
		byte(v>>8), byte(v),
	)
}

func appendChunkIP4(buf []byte, t uint16, ip net.IP) []byte {
	if len(ip) == 0 {
		return buf
	}
	ip4 := ip.To4()
	if ip4 == nil {
		return buf
	}
	buf = appendChunkHeader(buf, t, 4)
	return append(buf, ip4...)
}

func appendChunkIP6(buf []byte, t uint16, ip net.IP) []byte {
	if len(ip) != 16 {
		return buf
	}
	buf = appendChunkHeader(buf, t, 16)
	return append(buf, ip...)
}

func appendChunkBytes(buf []byte, t uint16, b []byte) []byte {
	if len(b) == 0 {
		return buf
	}
	buf = appendChunkHeader(buf, t, len(b))
	return append(buf, b...)
}

func appendChunkString(buf []byte, t uint16, s string) []byte {
	if s == "" {
		return buf
	}
	buf = appendChunkHeader(buf, t, len(s))
	return append(buf, s...)
}
