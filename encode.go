package main

import (
	"bytes"
	"encoding/binary"
	"log"
	"net"
)

const (
	bgpVersion = 4

	// BGP message types
	open         = 1
	update       = 2
	notification = 3
	keepalive    = 4
	refresh      = 5

	// as_path values
	asSet      = 1
	asSequence = 2

	// Error codes
	headerError     = 1
	openError       = 2
	updateError     = 3
	holdTimeExpired = 4
	fsmError        = 5
	cease           = 6

	// min and max BGP message size in bytes
	minMessage = 19
	maxMessage = 4096

	// AFI/SAFI
	afiIPv4     uint16 = 1
	afiIPv6     uint16 = 2
	safiUnicast uint8  = 1
)

type bgpid [4]byte
type ipv4Address []byte
type ipv6Address []byte

type twoByteLength [2]byte

type v4Addr struct {
	Mask   uint8
	Prefix net.IP
}

type v6Addr struct {
	Mask   uint8
	Prefix net.IP
}

type marker struct {
	//This 16-octet field is included for compatibility
	// It MUST be set to all ones.
	_ uint64
	_ uint64
}

type header struct {
	Length uint16
	Type   uint8
}

type msgOpen struct {
	Version  uint8
	ASN      uint16
	HoldTime uint16
	BGPID    bgpid
	ParamLen uint8
}

// Must be a better way...
func sizeOfStruct(i interface{}) int {
	buf := &bytes.Buffer{}
	binary.Write(buf, binary.BigEndian, i)
	return len(buf.Bytes())

}

// BGP packets start with 16 bytes of FF
func getMarker(b *bytes.Buffer) {
	// Always start a new packet by ensuring the buffer is flushed.
	b.Reset()
	b.Write([]byte{0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF})
}

// Keepalives are minimum size with a type code of keepalive
func (p *peer) createKeepAlive() {
	getMarker(p.out)
	k := []byte{0, 0, keepalive}
	p.out.Write(k)
}

// Encode packet over the wire
func (p *peer) encodeOutgoing() {
	// Set size
	b := p.out.Bytes()
	setSizeOfMessage(&b)
	log.Printf("Will encode the following...")
	log.Printf("%#v\n", b)
	binary.Write(p.conn, binary.BigEndian, b)
}

func setSizeOfMessage(b *[]byte) {
	s := uint16ToByte(uint16(len(*b)))
	(*b)[16] = s[0]
	(*b)[17] = s[1]
}

func (p *peer) createOpen() {
	getMarker(p.out)
	// Need to convert both ASN and Holdtime to [2]byte. Another function?
	p.out.Write([]byte{0, 0, open, bgpVersion})
	p.out.Write(getOpenASN(p.asn))
	p.out.Write(uint16ToByte(p.holdtime))
	p.out.Write(p.rid[:])

	// Add parameters
	param, len := createParameters(&p.param, p.asn)
	p.out.Write([]byte{len})
	p.out.Write(param)
}

func getOpenASN(asn uint16) []byte {
	// If 32bit ASN, open message will contain AS23456
	if asn == 23456 {
		return []byte{0x5b, 0xa0}
	}
	return uint16ToByte(asn)

}

func uint16ToByte(i uint16) []byte {
	a := i / 256
	b := i % 256
	return []byte{byte(a), byte(b)}
}

func uint32ToByte(i uint32) []byte {
	a := i / 16777216
	b := i / 65536
	c := i / 256
	d := i % 256
	return []byte{byte(a), byte(b), byte(c), byte(d)}
}

// How to look after each parameter in turn?
// Could be dodgy and encode cap 2 and size in each...
func createParameters(p *parameters, asn uint16) ([]byte, uint8) {
	var param []byte

	// length of parameters are worked out at the end
	param = append(param, uint8(2), 0)

	// Always send refresh and 4byte support
	param = append(param, byte(capRefresh), 0)
	param = append(param, byte(cap4Byte), 4)
	if p.ASN32 != 0 {
		param = append(param, byte(p.ASN32))
	} else {
		param = append(param, 0, 0)
		param = append(param, uint16ToByte(asn)...)
	}

	// Need to check which AF the peer is actually using!
	// AFI 0 SAFI 0 are IPv4, so if not filled in this is what is sent back :/
	// This might be fine. Advertise all but we'll negotiate on what the other sends.
	ip4 := createIPv4Cap()
	param = append(param, ip4...)
	ip6 := createIPv6Cap()
	param = append(param, ip6...)

	// Insert size of parameters. This is the total size minus the parameter type and size bytes
	param[1] = byte(len(param) - 2)

	return param, uint8(len(param))
}

// This isn't great
func createIPv4Cap() []byte {
	// Unknown numbers!
	return []byte{capMpBgp, 4, 0, 1, 0, 1}
}

func createIPv6Cap() []byte {
	// Unknown numbers!
	return []byte{capMpBgp, 4, 0, 2, 0, 1}
}

type parameterHeader struct {
	Type   uint8
	Length uint8
}

type msgCapability struct {
	Code   uint8
	Length uint8
}

type optGres struct {
	Restart uint8
	Time    uint8
}

type opt4Byte struct {
	ASN uint32
}

type msgNotification struct {
	Code    uint8
	Subcode uint8
}

// this is just for End-Of-RIB. Needs more work!
type msgUpdate struct {
	Withdraws  uint16
	AttrLength twoByteLength
}

func (t twoByteLength) toUint16() uint16 {
	return uint16(int(t[0])*256 + int(t[1]))
}

func (t twoByteLength) toInt64() int64 {
	return int64(t.toUint16())
}
