package main

import (
	"bytes"
	"encoding/binary"
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
	ID     uint32
}

type v6Addr struct {
	Mask   uint8
	Prefix net.IP
	ID     uint32
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
	//log.Printf("Will encode the following...")
	//log.Printf("%#v\n", b)
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
	// First two bytes zero as they will be updated to contain the length later
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

//TODO: Buggy, test!
func createParameters(p *parameters, asn uint16) ([]byte, uint8) {
	var param []byte

	initial := []byte{
		2, // Parameter Type
		0, // Length. Adjusted at the end
		capRefresh,
		0, // refresh is always size 0
		cap4Byte,
		4, // 4 byte ASN is always size 4
	}
	param = append(param, initial...)

	// TODO: Test this both on real router and test code
	if isASN32(p.ASN32) {
		param = append(param, p.ASN32[:]...)
	} else {
		param = append(param, 0, 0)
		param = append(param, uint16ToByte(asn)...)
	}

	// Only advertise the AF family that the peer sends us
	for _, a := range p.AddrFamilies {
		if isIPv4Unicast(a) {
			ip4 := createIPv4Cap()
			param = append(param, ip4...)
		}
		if isIPv6Unicast(a) {
			ip6 := createIPv6Cap()
			param = append(param, ip6...)
		}
	}

	for _, a := range p.AddPath {
		if isIPv4Unicast(a) {
			ip4 := createIPv4AddPath()
			param = append(param, ip4...)
		}
		if isIPv6Unicast(a) {
			ip6 := createIPv6AddPath()
			param = append(param, ip6...)
		}
	}

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

func createIPv4AddPath() []byte {
	// TODO: All these should be in a single function and documented.
	// Last digit is 1 because I only support receiving multiple paths
	return []byte{capAddPath, 4, 0, 1, 1, 1}
}

func createIPv6AddPath() []byte {
	// TODO: All these should be in a single function and documented.
	// Last digit is 1 because I only support receiving multiple paths
	return []byte{capAddPath, 4, 0, 2, 1, 1}
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

func (t twoByteLength) toUint16() uint16 {
	return uint16(int(t[0])*256 + int(t[1]))
}

func (t twoByteLength) toInt64() int64 {
	return int64(t.toUint16())
}

// If ASN field is all zeros, there is no 32bit ASN
func isASN32(asn [4]byte) bool {
	empty := [4]byte{}
	return !bytes.Equal(empty[:], asn[:])
}
