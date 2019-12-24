package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"io/ioutil"
	"log"
)

const (

	// Open optional parameter types
	capabilities = 2

	// capability codes I support
	// https://www.iana.org/assignments/capability-codes/capability-codes.xhtml
	capMpBgp   uint8 = 1
	cap4Byte   uint8 = 65
	capAddPath uint8 = 69
	capRefresh uint8 = 70 // Only support enhanced refresh
)

type parameters struct {
	ASN32        [4]byte
	Refresh      bool
	AddPath      []addr
	AddrFamilies []addr
	Supported    []uint8
	Unsupported  []uint8
}

type addr struct {
	AFI  uint16
	_    uint8
	SAFI uint8
}

func decodeOptionalParameters(param *[]byte) parameters {
	r := bytes.NewReader(*param)

	var par parameters
	par.AddrFamilies = []addr{}

	for {
		// Parameter header contains the optional parameters header and length in total.
		var p parameterHeader
		binary.Read(r, binary.BigEndian, &p)
		if r.Len() == 0 {
			break
		}

		// Pass all capabilties to be decoded. Depending on vendor,
		// there could be 1 or more capability per optional parameter.
		c := make([]byte, p.Length)
		io.ReadFull(r, c)
		decodeCapability(c, &par)
	}
	return par
}

func decodeCapability(cap []byte, p *parameters) {
	r := bytes.NewReader(cap)
	// There may be 1 or more capabilities per call.
	for {
		if r.Len() == 0 {
			break
		}
		var cap msgCapability
		binary.Read(r, binary.BigEndian, &cap)

		buf := bytes.NewBuffer(make([]byte, 0, cap.Length))
		switch cap.Code {

		case cap4Byte:
			log.Printf("4byte ASN supported")
			io.CopyN(buf, r, int64(cap.Length))
			log.Printf("%#v\n", buf)
			p.ASN32 = decode4OctetAS(buf)
			p.Supported = append(p.Supported, cap.Code)

		case capMpBgp:
			log.Printf("Multiprotocol Extenstions supported")
			io.CopyN(buf, r, int64(cap.Length))
			log.Printf("%#v\n", buf)
			addr := decodeMPBGP(buf)
			log.Printf("AFI is %d, SAFI is %d\n", addr.AFI, addr.SAFI)
			p.AddrFamilies = append(p.AddrFamilies, addr)
			p.Supported = append(p.Supported, cap.Code)

		case capRefresh:
			log.Printf("Enhanced Route Refresh supported")
			p.Refresh = true
			p.Supported = append(p.Supported, cap.Code)

		case capAddPath:
			log.Printf("AddPath advertised")
			io.CopyN(buf, r, int64(cap.Length))
			log.Printf("%#v\n", buf)
			addr, ok := decodeAddPath(buf)
			if !ok {
				log.Printf("Peer is not configured to send multiple paths")
				continue
			}
			log.Printf("AddPath supported")
			p.AddPath = append(p.AddPath, addr)
			p.Supported = append(p.Supported, cap.Code)

		default:
			log.Printf("Capability Code %d is unsupported", cap.Code)
			p.Unsupported = append(p.Unsupported, cap.Code)
			// As capability is not supported, drop the rest of the capability message.
			io.CopyN(ioutil.Discard, r, int64(cap.Length))
		}
	}
}

// parameter 65 is 4-octet AS support
func decode4OctetAS(b *bytes.Buffer) [4]byte {
	var ASN [4]byte
	binary.Read(b, binary.BigEndian, &ASN)
	log.Printf("%#v\n", ASN)
	log.Println(ASN)
	return ASN
}

func decodeMPBGP(b *bytes.Buffer) addr {
	var afisafi addr
	binary.Read(b, binary.BigEndian, &afisafi)
	return afisafi
}

// Only support AddPath if peer can send multiple paths, else not supported.
func decodeAddPath(b *bytes.Buffer) (addr, bool) {
	var adp struct {
		Afi     uint16
		Safi    uint8
		SendRec uint8
	}
	binary.Read(b, binary.BigEndian, &adp)
	log.Printf("%+v\n", adp)

	// 2 means peer can send us multiple paths, 3 means both send and receive.
	// 1 means peer can only receive.
	if adp.SendRec == 2 || adp.SendRec == 3 {
		return addr{
			AFI:  adp.Afi,
			SAFI: adp.Safi,
		}, true

	}
	return addr{}, false
}

// TODO These should be methods attached to the struct
func isIPv4Unicast(a addr) bool {
	return a.AFI == 1 && a.SAFI == 1
}

func isIPv6Unicast(a addr) bool {
	return a.AFI == 2 && a.SAFI == 1
}
