package bgp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
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

var (
	// Some attributes here were deprecated a while back, while others
	// were added in RFC8093
	isDeprecated = map[uint8]bool{
		11:  true,
		12:  true,
		13:  true,
		19:  true,
		20:  true,
		21:  true,
		28:  true,
		30:  true,
		31:  true,
		129: true,
		241: true,
		242: true,
		243: true,
		50:  true,
	}
)

type attrHeader struct {
	Type flagType
}

type flagType struct {
	Flags byte
	Code  uint8
}

type Origin uint8

func (o Origin) String() string {
	switch uint8(o) {
	case 0:
		return "IGP"
	case 1:
		return "EGP"
	case 2:
		return "INCOMPLETE"
	}
	return ""
}

type PathAttr struct {
	Origin            Origin
	Aspath            []AsnSegment
	NextHopv4         string
	Med               uint32
	LocalPref         uint32
	Atomic            bool
	AgAS              uint32
	AgOrigin          net.IP
	Originator        string
	ClusterList       []string
	Communities       []Community
	LargeCommunities  []LargeCommunity
	ExtendCommunities []ExtendCommunity
	NextHopsv6        []string
	Ipv6NLRI          []V6Addr
	V6Withdraws       []V6Addr
	V6EoR             bool
}

type Community struct {
	High uint16
	Low  uint16
}

type LargeCommunity struct {
	Admin uint32
	High  uint32
	Low   uint32
}

type ExtendCommunity struct {
}

type PrefixAttributes struct {
	Attr        *PathAttr
	V4prefixes  []V4Addr
	V6prefixes  []V6Addr
	V4Withdraws []V4Addr
	V6Withdraws []V6Addr
	V4NextHop  string
	V6NextHops []string
	V4EoR      bool
	V6EoR      bool
}

type V4Addr struct {
	Mask   uint8
	Prefix net.IP
	ID     uint32
}

type V6Addr struct {
	Mask   uint8
	Prefix net.IP
	ID     uint32
}

// DecodePathAttributes decodes the BGP Path Attributes from an UPDATE message.
func DecodePathAttributes(attr []byte, v6AddPath bool, ignoreComms bool) (*PathAttr, error) {
	r := bytes.NewReader(attr)

	var pa PathAttr
	for {
		if r.Len() == 0 {
			break
		}
		var ah attrHeader
		if err := binary.Read(r, binary.BigEndian, &ah); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}

		buf := new(bytes.Buffer)

		var length64 int64
		if isExtended(ah.Type.Flags) {
			var length uint16
			if err := binary.Read(r, binary.BigEndian, &length); err != nil {
				return nil, err
			}
			length64 = int64(length)
		} else {
			var length uint8
			if err := binary.Read(r, binary.BigEndian, &length); err != nil {
				return nil, err
			}
			length64 = int64(length)
		}

		if _, err := io.CopyN(buf, r, length64); err != nil {
			return nil, err
		}

		var err error
		switch ah.Type.Code {
		case tcOrigin:
			pa.Origin, err = decodeOrigin(buf)
		case tcASPath:
			for buf.Len() > 0 {
				var asns []AsnSegment
				asns, err = decodeASPath(buf)
				if err != nil {
					break
				}
				pa.Aspath = append(pa.Aspath, asns...)
			}
		case tcNextHop:
			pa.NextHopv4, err = decode4byteIPv4(buf)
		case tcMED:
			pa.Med, err = decode4ByteNumber(buf)
		case tcLPref:
			pa.LocalPref, err = decode4ByteNumber(buf)
		case tcAtoAgg:
			pa.Atomic = true
		case tcAggregator:
			pa.AgAS, pa.AgOrigin, err = decodeAggregator(buf)
		case tcMPReachNLRI:
			pa.Ipv6NLRI, pa.NextHopsv6, err = decodeMPReachNLRI(buf, v6AddPath)
		case tcMPUnreachNLRI:
			pa.V6EoR, pa.V6Withdraws, err = decodeMPUnreachNLRI(buf, length64, v6AddPath)
		case tcCommunity:
			if ignoreComms {
				_, err = io.CopyN(io.Discard, buf, length64)
				continue
			}
			pa.Communities, err = decodeCommunities(buf, length64)
		case tcLargeCommunity:
			if ignoreComms {
				_, err = io.CopyN(io.Discard, buf, length64)
				continue
			}
			pa.LargeCommunities, err = decodeLargeCommunities(buf, length64)
		case tcExtendCommunity:
			if ignoreComms {
				_, err = io.CopyN(io.Discard, buf, length64)
				continue
			}
			pa.ExtendCommunities, err = decodeExtendedCommunities(buf, length64)
		case tcOriginator:
			pa.Originator, err = decode4byteIPv4(buf)
		case tcClusterList:
			pa.ClusterList, err = decodeClusterList(buf, length64)

		default:
			_, err = io.CopyN(io.Discard, buf, length64)
		}

		if err != nil {
			return nil, err
		}

		if isDeprecated[ah.Type.Code] {
			log.Printf("Type Code %d is deprecated", ah.Type.Code)
		}
	}
	return &pa, nil
}

func isExtended(b byte) bool {
	return b&16 == 16
}

func decodeOrigin(b *bytes.Buffer) (Origin, error) {
	var o Origin
	if err := binary.Read(b, binary.BigEndian, &o); err != nil {
		return o, err
	}
	return o, nil
}

func decode4byteIPv4(b *bytes.Buffer) (string, error) {
	ip := make([]byte, 4)
	if _, err := io.ReadFull(b, ip); err != nil {
		return "", err
	}
	return net.IP(ip).String(), nil
}

func decode16byteIPv6(b *bytes.Buffer) (string, error) {
	ip := make([]byte, 16)
	if _, err := io.ReadFull(b, ip); err != nil {
		return "", err
	}
	return net.IP(ip).String(), nil
}

func decode4ByteNumber(b *bytes.Buffer) (uint32, error) {
	var n uint32
	if err := binary.Read(b, binary.BigEndian, &n); err != nil {
		return n, err
	}
	return n, nil
}

type asnTL struct {
	Type   uint8
	Length uint8
}

type AsnSegment struct {
	Type uint8
	ASN  uint32
}

func decodeASPath(b *bytes.Buffer) ([]AsnSegment, error) {
	var tl asnTL
	if err := binary.Read(b, binary.BigEndian, &tl); err != nil {
		return nil, err
	}
	var asns = make([]AsnSegment, tl.Length)
	for i := uint8(0); i < tl.Length; i++ {
		var asn AsnSegment
		asn.Type = tl.Type
		if err := binary.Read(b, binary.BigEndian, &asn.ASN); err != nil {
			return nil, err
		}
		asns[i] = asn
	}
	return asns, nil
}

func decodeAggregator(b *bytes.Buffer) (uint32, net.IP, error) {
	var asn uint32
	if err := binary.Read(b, binary.BigEndian, &asn); err != nil {
		return 0, nil, err
	}
	ip := make([]byte, 4)
	if _, err := io.ReadFull(b, ip); err != nil {
		return 0, nil, err
	}
	return asn, net.IP(ip), nil
}

func decodeCommunities(b *bytes.Buffer, length int64) ([]Community, error) {
	var communities = make([]Community, 0, length/4)
	for b.Len() > 0 {
		var comm Community
		if err := binary.Read(b, binary.BigEndian, &comm); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		communities = append(communities, comm)
	}
	return communities, nil
}

func decodeLargeCommunities(b *bytes.Buffer, length int64) ([]LargeCommunity, error) {
	var communities = make([]LargeCommunity, 0, length/12)
	for b.Len() > 0 {
		var comm LargeCommunity
		if err := binary.Read(b, binary.BigEndian, &comm); err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		communities = append(communities, comm)
	}
	return communities, nil
}

func decodeExtendedCommunities(b *bytes.Buffer, length int64) ([]ExtendCommunity, error) {
	if _, err := io.CopyN(io.Discard, b, length); err != nil {
		return nil, err
	}
	return nil, nil
}

func decodeClusterList(b *bytes.Buffer, length int64) ([]string, error) {
	ids := int(length / 4)
	var cluster = make([]string, 0, ids)
	for i := 0; i < ids; i++ {
		str, err := decode4byteIPv4(b)
		if err != nil {
			return nil, err
		}
		cluster = append(cluster, str)
	}
	return cluster, nil
}

// DecodeIPv4NLRI decodes IPv4 NLRI prefixes.
func DecodeIPv4NLRI(b *bytes.Reader, addPath bool) ([]V4Addr, error) {
	var addrs []V4Addr
	for b.Len() > 0 {
		var id uint32
		if addPath {
			if err := binary.Read(b, binary.BigEndian, &id); err != nil {
				return nil, err
			}
		}

		var mask uint8
		if err := binary.Read(b, binary.BigEndian, &mask); err != nil {
			return nil, err
		}

		prefix, err := getIPv4Prefix(b, mask)
		if err != nil {
			return nil, err
		}

		addrs = append(addrs, V4Addr{
			Mask:   mask,
			Prefix: prefix,
			ID:     id,
		})
	}
	return addrs, nil
}

func decodeIPv6NLRI(b *bytes.Buffer, addPath bool) ([]V6Addr, error) {
	var addrs []V6Addr
	for b.Len() > 0 {
		var id uint32
		if addPath {
			if err := binary.Read(b, binary.BigEndian, &id); err != nil {
				return nil, err
			}
		}

		var mask uint8
		if err := binary.Read(b, binary.BigEndian, &mask); err != nil {
			return nil, err
		}

		prefix, err := getIPv6Prefix(b, mask)
		if err != nil {
			return nil, err
		}

		addrs = append(addrs, V6Addr{
			Mask:   mask,
			Prefix: prefix,
			ID:     id,
		})
	}
	return addrs, nil
}

func getIPv4Prefix(b *bytes.Reader, mask uint8) (net.IP, error) {
	if mask > 32 {
		return nil, fmt.Errorf("invalid IPv4 mask: %d", mask)
	}
	numBytes := (int(mask) + 7) / 8
	ip := make([]byte, 4)
	if _, err := io.ReadFull(b, ip[:numBytes]); err != nil {
		return nil, err
	}
	return net.IP(ip), nil
}

func getIPv6Prefix(b *bytes.Buffer, mask uint8) (net.IP, error) {
	if mask > 128 {
		return nil, fmt.Errorf("invalid IPv6 mask: %d", mask)
	}
	numBytes := (int(mask) + 7) / 8
	ip := make([]byte, 16)
	if _, err := io.ReadFull(b, ip[:numBytes]); err != nil {
		return nil, err
	}
	return net.IP(ip), nil
}

func decodeMPReachNLRI(b *bytes.Buffer, addPath bool) ([]V6Addr, []string, error) {
	var afi uint16
	var safi uint8
	if err := binary.Read(b, binary.BigEndian, &afi); err != nil {
		return nil, nil, err
	}
	if err := binary.Read(b, binary.BigEndian, &safi); err != nil {
		return nil, nil, err
	}

	var nhLen uint8
	if err := binary.Read(b, binary.BigEndian, &nhLen); err != nil {
		return nil, nil, err
	}

	var nextHops []string
	nh := bytes.NewBuffer(make([]byte, 0, 16))
	if _, err := io.CopyN(nh, b, 16); err != nil {
		return nil, nil, err
	}
	ip, err := decode16byteIPv6(nh)
	if err != nil {
		return nil, nil, err
	}
	nextHops = append(nextHops, ip)

	if nhLen == 32 {
		llnh := bytes.NewBuffer(make([]byte, 0, 16))
		if _, err := io.CopyN(llnh, b, 16); err != nil {
			return nil, nil, err
		}
		llip, err := decode16byteIPv6(llnh)
		if err != nil {
			return nil, nil, err
		}
		nextHops = append(nextHops, llip)
	}

	// Skip SNPA
	b.Next(1)

	nlri, err := decodeIPv6NLRI(b, addPath)
	return nlri, nextHops, err
}

func decodeMPUnreachNLRI(b *bytes.Buffer, length int64, addPath bool) (bool, []V6Addr, error) {
	if length == 3 {
		b.Next(3)
		return true, nil, nil
	}
	b.Next(3)
	nlri, err := decodeIPv6NLRI(b, addPath)
	return false, nlri, err
}

// DecodeIPv4Withdraws decodes IPv4 withdrawals.
func DecodeIPv4Withdraws(wd []byte, addPath bool) (*PrefixAttributes, error) {
	r := bytes.NewReader(wd)
	var pa PrefixAttributes
	addrs, err := DecodeIPv4NLRI(r, addPath)
	if err != nil {
		return nil, err
	}
	pa.V4Withdraws = addrs
	return &pa, nil
}

// FormatASPath returns a formatted AS-PATH string.
func FormatASPath(asns *[]AsnSegment) string {
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

// FormatCommunities returns a formatted Communities string.
func FormatCommunities(com *[]Community) string {
	var b strings.Builder
	for _, v := range *com {
		b.WriteString(fmt.Sprintf("%d:%d ", v.High, v.Low))
	}
	return strings.TrimSpace(b.String())
}

// FormatLargeCommunities returns a formatted Large Communities string.
func FormatLargeCommunities(com *[]LargeCommunity) string {
	var b strings.Builder
	for _, v := range *com {
		b.WriteString(fmt.Sprintf("%d:%d:%d ", v.Admin, v.High, v.Low))
	}
	return strings.TrimSpace(b.String())
}

// FormatClusterList returns a formatted Cluster List string.
func FormatClusterList(cluster *[]string) string {
	var b strings.Builder
	for _, v := range *cluster {
		b.WriteString(fmt.Sprintf("%s, ", v))
	}
	return strings.TrimRight(b.String(), ", ")
}
