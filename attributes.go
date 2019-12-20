package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"strconv"
	"strings"
)

const (
	// Type Codes
	tcOrigin          = 1
	tcASPath          = 2
	tcNextHop         = 3
	tcMED             = 4
	tcLPref           = 5
	tcAtoAgg          = 6
	tcAggregator      = 7
	tcCommunity       = 8
	tcOriginator      = 9
	tcClusterList     = 10
	tcMPReachNLRI     = 14
	tcExtendCommunity = 16
	tcMPUnreachNLRI   = 15
	tcLargeCommunity  = 32
)

type attrHeader struct {
	Type flagType
}

type flagType struct {
	Flags byte
	Code  uint8
}

type origin uint8

// TODO: Where should this go?
func (o *origin) string() string {
	switch uint8(*o) {
	case 0:
		return "IGP"
	case 1:
		return "EGP"
	case 2:
		return "INCOMPLETE"
	}
	return ""
}

type pathAttr struct {
	origin            origin
	aspath            []asnSegment
	nextHopv4         string
	med               uint32
	localPref         uint32
	atomic            bool
	agAS              uint32
	agOrigin          net.IP
	originator        net.IP
	communities       []community
	largeCommunities  []largeCommunity
	extendCommunities []extendCommunity
	nextHopsv6        []string
	ipv6NLRI          []v6Addr
	v6EoR             bool
}

type community struct {
	High uint16
	Low  uint16
}

type largeCommunity struct {
	Admin uint32
	High  uint32
	Low   uint32
}

type extendCommunity struct {
}

type prefixAttributes struct {
	attr       *pathAttr
	v4prefixes []v4Addr
	v6prefixes []v6Addr
	v6NextHops []string
	v4EoR      bool
	v6EoR      bool
}

func decodePathAttributes(attr []byte) *pathAttr {
	r := bytes.NewReader(attr)

	var pa pathAttr
	for {
		if r.Len() == 0 {
			break
		}
		var ah attrHeader
		binary.Read(r, binary.BigEndian, &ah)

		// Is this of size 64 by default?
		// TODO: check
		buf := new(bytes.Buffer)

		// Extended length means length field is two bytes, else one
		// TODO: This should all go into a new function
		var len int64
		if isExtended(ah.Type.Flags) {
			var length uint16
			binary.Read(r, binary.BigEndian, &length)
			len = int64(length)
		} else {
			var length uint8
			binary.Read(r, binary.BigEndian, &length)
			len = int64(length)
		}

		// Copy the entire attribute into a new buffer
		io.CopyN(buf, r, len)

		switch ah.Type.Code {
		case tcOrigin:
			pa.origin = decodeOrigin(buf)
		case tcASPath:
			pa.aspath = append(pa.aspath, decodeASPath(buf)...)
			// Could have both AS_SEQ and AS_SET
			if r.Len() != 0 {
				pa.aspath = append(pa.aspath, decodeASPath(buf)...)
			}
		case tcNextHop:
			pa.nextHopv4 = decodeIPv4NextHop(buf)
		case tcMED:
			pa.med = decode4ByteNumber(buf)
		case tcLPref:
			pa.localPref = decode4ByteNumber(buf)
		case tcAtoAgg:
			pa.atomic = true
		case tcAggregator:
			pa.agAS, pa.agOrigin = decodeAggregator(buf)
		case tcMPReachNLRI:
			pa.ipv6NLRI, pa.nextHopsv6 = decodeMPReachNLRI(buf)
		case tcMPUnreachNLRI:
			pa.v6EoR = decodeMPUnreachNLRI(buf, 3)
		case tcCommunity:
			pa.communities = decodeCommunities(buf, len)
		case tcLargeCommunity:
			pa.largeCommunities = decodeLargeCommunities(buf, len)
		case tcExtendCommunity:
			pa.extendCommunities = decodeExtendedCommunities(buf, len)
		case tcOriginator:
			pa.originator = decodeOriginator(buf)

		default:
			log.Printf("Type Code %d is not yet implemented", ah.Type.Code)
		}
	}
	return &pa
}

// Extended-length means two bytes, else one
func isExtended(b byte) bool {
	res := b & 16
	return res == 16
}

func decodeOrigin(b *bytes.Buffer) origin {
	var o origin
	binary.Read(b, binary.BigEndian, &o)

	return o
}

// Originator is set by the RR when a route is reflected.
func decodeOriginator(b *bytes.Buffer) net.IP {
	o := bytes.NewBuffer(make([]byte, 0, 4))
	io.Copy(o, b)
	return net.IP(o.Bytes())
}

// TODO: The actual IPv4 address should be a generic function. There
// are numerous capabilities that require an IP address or router ID.
func decodeIPv4NextHop(b *bytes.Buffer) string {
	ip := bytes.NewBuffer(make([]byte, 0, 4))
	io.Copy(ip, b)
	return net.IP(ip.Bytes()).String()
}

func decodeIPv6NextHop(b *bytes.Buffer) string {
	ip := bytes.NewBuffer(make([]byte, 0, 16))
	io.Copy(ip, b)
	return net.IP(ip.Bytes()).String()
}

func decode4ByteNumber(b *bytes.Buffer) uint32 {
	var n uint32
	binary.Read(b, binary.BigEndian, &n)
	return n
}

type asnTL struct {
	Type   uint8
	Length uint8
}

type asnSegment struct {
	Type uint8
	ASN  uint32
}

// If empty, could be iBGP update and so should deal with that
func decodeASPath(b *bytes.Buffer) []asnSegment {
	var asnTL asnTL
	binary.Read(b, binary.BigEndian, &asnTL)
	var asns = make([]asnSegment, asnTL.Length)
	for i := uint8(0); i < asnTL.Length; i++ {
		var asn asnSegment
		asn.Type = asnTL.Type
		binary.Read(b, binary.BigEndian, &asn.ASN)
		asns[i] = asn
	}
	return asns
}

func decodeAggregator(b *bytes.Buffer) (uint32, net.IP) {
	ip := bytes.NewBuffer(make([]byte, 0, 4))
	var asn uint32
	binary.Read(b, binary.BigEndian, &asn)
	io.Copy(ip, b)
	return asn, net.IP(ip.Bytes())
}

func decodeCommunities(b *bytes.Buffer, len int64) []community {
	// Each community takes 4 bytes
	var communities = make([]community, 0, len/4)
	for {
		if b.Len() == 0 {
			break
		}
		var comm community
		binary.Read(b, binary.BigEndian, &comm)
		communities = append(communities, comm)
	}
	return communities
}

func decodeLargeCommunities(b *bytes.Buffer, len int64) []largeCommunity {
	// Each large community takes 12 bytes
	var communities = make([]largeCommunity, 0, len/12)
	for {
		if b.Len() == 0 {
			break
		}
		var comm largeCommunity
		binary.Read(b, binary.BigEndian, &comm)
		communities = append(communities, comm)
	}
	return communities
}

// TODO: Extended communities can hold many different things so this function itself
// can end up very complicated. Maybe just dump the bytes? A bit nasty so maybe not.
// For now just null0 the update
// rfc4360
func decodeExtendedCommunities(b *bytes.Buffer, len int64) []extendCommunity {
	io.CopyN(ioutil.Discard, b, len)
	return nil
}

func decodeIPv4NLRI(b *bytes.Reader) []v4Addr {
	var addrs []v4Addr
	for {
		if b.Len() == 0 {
			break
		}

		var mask uint8
		binary.Read(b, binary.BigEndian, &mask)

		addrs = append(addrs, v4Addr{
			Mask:   mask,
			Prefix: getIPv4Prefix(b, mask),
		})
	}

	return addrs
}

// BGP only encodes the prefix up to the subnet value in bits, and then pads zeros until the end of the octet.
func getIPv4Prefix(b *bytes.Reader, mask uint8) net.IP {
	prefix := bytes.NewBuffer(make([]byte, 0, 4))

	switch {
	case mask >= 1 && mask <= 8:
		io.CopyN(prefix, b, 1)
	case mask >= 9 && mask <= 16:
		io.CopyN(prefix, b, 2)
	case mask >= 17 && mask <= 24:
		io.CopyN(prefix, b, 3)
	case mask >= 25:
		io.CopyN(prefix, b, 4)
	}

	// IPv4 net.IP requires all bytes to have values, including zeros
	// TODO: But so does IPv6? Do the same as what I'm doing there?
	return fillv4(prefix.Bytes())
}

// TODO: test cases
func fillv4(b []byte) net.IP {
	fill := make([]byte, 4-len(b))
	b = append(b, fill...)
	return net.IP(b)
}

// BGP only encodes the prefix up to the subnet value in bits, and then pads zeros until the end of the octet.
func getIPv6Prefix(b *bytes.Buffer, mask uint8) net.IP {
	prefix := bytes.NewBuffer(make([]byte, 0, 16))

	switch {
	case mask >= 1 && mask <= 8:
		io.CopyN(prefix, b, 1)
	case mask >= 9 && mask <= 16:
		io.CopyN(prefix, b, 2)
	case mask >= 17 && mask <= 24:
		io.CopyN(prefix, b, 3)
	case mask >= 25 && mask <= 32:
		io.CopyN(prefix, b, 4)
	case mask >= 33 && mask <= 40:
		io.CopyN(prefix, b, 5)
	case mask >= 41 && mask <= 48:
		io.CopyN(prefix, b, 6)
	case mask >= 49 && mask <= 56:
		io.CopyN(prefix, b, 7)
	case mask >= 57 && mask <= 64:
		io.CopyN(prefix, b, 8)
	case mask >= 65 && mask <= 72:
		io.CopyN(prefix, b, 9)
	case mask >= 73 && mask <= 80:
		io.CopyN(prefix, b, 10)
	case mask >= 81 && mask <= 88:
		io.CopyN(prefix, b, 11)
	case mask >= 89 && mask <= 96:
		io.CopyN(prefix, b, 12)
	case mask >= 97 && mask <= 104:
		io.CopyN(prefix, b, 13)
	case mask >= 105 && mask <= 112:
		io.CopyN(prefix, b, 14)
	case mask >= 113 && mask <= 120:
		io.CopyN(prefix, b, 15)
	case mask >= 121 && mask <= 128:
		io.CopyN(prefix, b, 16)
	}

	for prefix.Len() < 16 {
		prefix.WriteByte(0)
	}

	return net.IP(prefix.Bytes())
}

func decodeMPReachNLRI(b *bytes.Buffer) ([]v6Addr, []string) {
	// AFI/SAFI - For now I only IPv6 Unicast
	var afi uint16
	var safi uint8
	// Could be two next-hops
	var nextHops []string
	binary.Read(b, binary.BigEndian, &afi)
	binary.Read(b, binary.BigEndian, &safi)
	log.Println(afi)
	log.Println(safi)
	// In the above, I'm really only supporting IPv6 here. The rest is dependant on which AFI/SAFI

	// If the next-hop length is 32 bytes, we have both a public and link-local
	// If the next-hop length is only 16 bytes, the next-hop should be public only
	// But if the actual next-hop is link-local, the initial next-hop is :: ?
	var nhLen uint8
	binary.Read(b, binary.BigEndian, &nhLen)
	log.Println(nhLen)

	nh := bytes.NewBuffer(make([]byte, 0, 16))
	io.CopyN(nh, b, 16)
	nextHops = append(nextHops, decodeIPv6NextHop(nh))

	if nhLen == 32 {
		llnh := bytes.NewBuffer(make([]byte, 0, 16))
		io.CopyN(llnh, b, 16)
		nextHops = append(nextHops, decodeIPv6NextHop(llnh))
	}

	// Ignore one byte SNPA
	io.CopyN(ioutil.Discard, b, 1)

	// Pass the remainder of the buffer to be decoded into NLRI
	return decodeIPv6NLRI(b), nextHops

}

// TODO: finish this off...
func decodeMPUnreachNLRI(b *bytes.Buffer, len int64) bool {
	if len == 3 {
		return true
	}
	return false
}

// BGP only encodes the prefix up to the subnet value in bits, and then pads zeros until the end of the octet.
func decodeIPv6NLRI(b *bytes.Buffer) []v6Addr {
	var addrs []v6Addr
	for {
		if b.Len() == 0 {
			break
		}

		var mask uint8
		binary.Read(b, binary.BigEndian, &mask)

		addrs = append(addrs, v6Addr{
			Mask:   mask,
			Prefix: getIPv6Prefix(b, mask),
		})
	}
	return addrs
}

// TODO: this is awful. This is the same as decode IPv4 NLRI. Use the same?
func decodeIPv4Withdraws(wd []byte) *prefixAttributes {
	r := bytes.NewReader(wd)
	var pa prefixAttributes
	var addrs []v4Addr
	for {
		if r.Len() == 0 {
			break
		}

		var mask uint8
		binary.Read(r, binary.BigEndian, &mask)

		addrs = append(addrs, v4Addr{
			Mask:   mask,
			Prefix: getIPv4Prefix(r, mask),
		})
	}
	pa.v4prefixes = addrs

	return &pa
}

// Return a properly formatted AS-PATH. Sequnce AS-PATH
// are in front with spaces between, while the AS-SET is
// in curly braces at the end.
func formatASPath(asns *[]asnSegment) string {
	var sequence, set []int
	var b strings.Builder

	for _, asn := range *asns {
		if asn.Type == 2 {
			sequence = append(sequence, int(asn.ASN))
			continue
		}
		if asn.Type == 1 {
			set = append(set, int(asn.ASN))
		}
	}

	for _, v := range sequence {
		b.WriteString(strconv.Itoa(v) + " ")
	}
	if len(set) > 0 {
		b.WriteString("{ ")
		for _, v := range set {
			b.WriteString(strconv.Itoa(v) + " ")
		}
		b.WriteString("}")
	}

	return strings.TrimSpace(b.String())
}

func formatCommunities(com *[]community) string {
	var b strings.Builder
	for _, v := range *com {
		b.WriteString(fmt.Sprintf("%d:%d ", v.High, v.Low))
	}
	return strings.TrimSpace(b.String())
}

func formatLargeCommunities(com *[]largeCommunity) string {
	var b strings.Builder
	for _, v := range *com {
		b.WriteString(fmt.Sprintf("%d:%d:%d ", v.Admin, v.High, v.Low))
	}
	return strings.TrimSpace(b.String())
}
