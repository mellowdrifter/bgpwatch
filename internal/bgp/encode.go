package bgp

import (
	"bytes"
)

const (
	bgpVersion = 4

	// BGP message types
	Open         = 1
	Update       = 2
	Notification = 3
	Keepalive    = 4
	Refresh      = 5

	// as_path values
	asSet      = 1
	asSequence = 2

	// Error codes
	HeaderError     = 1
	OpenError       = 2
	UpdateError     = 3
	HoldTimeExpired = 4
	FsmError        = 5
	Cease           = 6

	// min and max BGP message size in bytes
	MinMessage = 19
	MaxMessage         = 4096
	MaxExtendedMessage = 65535

	// AFI/SAFI
	afiIPv4     uint16 = 1
	afiIPv6     uint16 = 2
	safiUnicast uint8  = 1
)

type BGPID [4]byte

type msgOpen struct {
	Version  uint8
	ASN      uint16
	HoldTime uint16
	BGPID    [4]byte
	ParamLen uint8
}

type msgNotification struct {
	Code    uint8
	Subcode uint8
}

// CreateKeepAlive creates a BGP KEEPALIVE message.
func CreateKeepAlive() []byte {
	var b bytes.Buffer
	writeMarker(&b)
	b.Write([]byte{0, 19, Keepalive})
	return b.Bytes()
}

// CreateOpen creates a BGP OPEN message.
func CreateOpen(asn uint32, holdtime uint16, rid BGPID, p *Parameters) []byte {
	var b bytes.Buffer
	writeMarker(&b)
	
	// Header placeholder
	b.Write([]byte{0, 0, Open})
	
	b.WriteByte(bgpVersion)
	b.Write(getOpenASN(asn))
	b.Write(uint16ToByte(holdtime))
	b.Write(rid[:])

	param, pLen := createParameters(p, asn)
	b.WriteByte(pLen)
	b.Write(param)

	buf := b.Bytes()
	setSizeOfMessage(&buf)
	return buf
}

// CreateNotification creates a BGP NOTIFICATION message.
func CreateNotification(code, subcode uint8) []byte {
	var b bytes.Buffer
	writeMarker(&b)
	b.Write([]byte{0, 0, Notification})
	b.WriteByte(code)
	b.WriteByte(subcode)
	
	buf := b.Bytes()
	setSizeOfMessage(&buf)
	return buf
}

func writeMarker(b *bytes.Buffer) {
	for i := 0; i < 16; i++ {
		b.WriteByte(0xFF)
	}
}

func setSizeOfMessage(b *[]byte) {
	s := uint16ToByte(uint16(len(*b)))
	(*b)[16] = s[0]
	(*b)[17] = s[1]
}

func getOpenASN(asn uint32) []byte {
	if asn > 65535 {
		return []byte{0x5b, 0xa0} // AS23456
	}
	return uint16ToByte(uint16(asn))
}

func uint16ToByte(i uint16) []byte {
	return []byte{byte(i >> 8), byte(i)}
}

func uint32ToByte(i uint32) []byte {
	return []byte{byte(i >> 24), byte(i >> 16), byte(i >> 8), byte(i)}
}

func createParameters(p *Parameters, asn uint32) ([]byte, uint8) {
	var param []byte

	initial := []byte{
		2, // Parameter Type: Capabilities
		0, // Length placeholder
		capRefresh,
		0, // refresh size 0
		cap4Byte,
		4, // 4 byte ASN size 4
		capExtendedMessage,
		0, // size 0
	}
	param = append(param, initial...)
	param = append(param, uint32ToByte(asn)...)

	for _, a := range p.AddrFamilies {
		if isIPv4Unicast(a) {
			param = append(param, []byte{capMpBgp, 4, 0, 1, 0, 1}...)
		}
		if isIPv6Unicast(a) {
			param = append(param, []byte{capMpBgp, 4, 0, 2, 0, 1}...)
		}
	}

	for _, a := range p.AddPath {
		if a.AFI == 1 && a.SAFI == 1 {
			param = append(param, []byte{capAddPath, 4, 0, 1, 1, 1}...)
		}
		if a.AFI == 2 && a.SAFI == 1 {
			param = append(param, []byte{capAddPath, 4, 0, 2, 1, 1}...)
		}
	}

	param[1] = byte(len(param) - 2)
	return param, uint8(len(param))
}

func isIPv4Unicast(a Addr) bool {
	return a.AFI == 1 && a.SAFI == 1
}

func isIPv6Unicast(a Addr) bool {
	return a.AFI == 2 && a.SAFI == 1
}
