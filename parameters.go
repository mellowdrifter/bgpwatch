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
	capRefresh uint8 = 70 // Only support enhanced refresh
)

type parameters struct {
	ASN32        uint32
	Refresh      bool
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

		// Pass all capabilties to be decoded. Depending on vendor, there could be 1 or more
		// capability per optional parameter.
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

		// Setting 20 here as a random number which should be big enough for any capability?
		buf := bytes.NewBuffer(make([]byte, 20))
		switch cap.Code {

		case cap4Byte:
			log.Printf("case cap4Byte")
			io.CopyN(buf, r, int64(cap.Length))
			p.ASN32 = decode4OctetAS(buf)
			p.Supported = append(p.Supported, cap.Code)

		case capMpBgp:
			log.Printf("case capMpBgp")
			io.CopyN(buf, r, int64(cap.Length))
			addr := decodeMPBGP(buf)
			log.Printf("AFI is %d, SAFI is %d\n", addr.AFI, addr.SAFI)
			p.AddrFamilies = append(p.AddrFamilies, addr)
			p.Supported = append(p.Supported, cap.Code)

		case capRefresh:
			log.Printf("case capRefresh")
			p.Refresh = true
			p.Supported = append(p.Supported, cap.Code)

		default:
			log.Printf("unsupported")
			p.Unsupported = append(p.Unsupported, cap.Code)
			// As capability is not supported, drop the rest of the capability message.
			io.CopyN(ioutil.Discard, r, int64(cap.Length))
		}
	}
}

// parameter 65 is 4-octet AS support
func decode4OctetAS(b *bytes.Buffer) uint32 {
	var ASN uint32
	binary.Read(b, binary.BigEndian, &ASN)
	return ASN
}

func decodeMPBGP(b *bytes.Buffer) addr {
	var afisafi addr
	binary.Read(b, binary.BigEndian, &afisafi)
	return afisafi
}
