package bgp

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
)

const (
	// Open optional parameter types
	capabilities = 2

	// capability codes I support
	capMpBgp   uint8 = 1
	cap4Byte   uint8 = 65
	capAddPath uint8 = 69
	capRefresh uint8 = 70 // Only support enhanced refresh
)

type Parameters struct {
	ASN32        [4]byte
	Refresh      bool
	AddPath      []AddPathCapability
	AddrFamilies []Addr
	Supported    []uint8
	Unsupported  []uint8
}

type Addr struct {
	AFI  uint16
	_    uint8
	SAFI uint8
}

type AddPathCapability struct {
	AFI         uint16
	SAFI        uint8
	SendReceive uint8 // 1 = receive, 2 = send, 3 = both
}

type parameterHeader struct {
	Type   uint8
	Length uint8
}

type msgCapability struct {
	Code   uint8
	Length uint8
}

// DecodeOptionalParameters decodes the BGP OPEN optional parameters.
func DecodeOptionalParameters(param *[]byte) (Parameters, error) {
	r := bytes.NewReader(*param)

	var par Parameters
	par.AddrFamilies = []Addr{}

	for {
		var p parameterHeader
		if err := binary.Read(r, binary.BigEndian, &p); err != nil {
			if err == io.EOF {
				break
			}
			return par, err
		}
		if r.Len() == 0 {
			break
		}

		c := make([]byte, p.Length)
		if _, err := io.ReadFull(r, c); err != nil {
			return par, err
		}
		if err := decodeCapability(c, &par); err != nil {
			return par, err
		}
	}
	return par, nil
}

func decodeCapability(cap []byte, p *Parameters) error {
	r := bytes.NewReader(cap)
	for {
		if r.Len() == 0 {
			break
		}
		var msgCap msgCapability
		if err := binary.Read(r, binary.BigEndian, &msgCap); err != nil {
			if err == io.EOF {
				break
			}
			return err
		}

		buf := bytes.NewBuffer(make([]byte, 0, msgCap.Length))
		switch msgCap.Code {
		case cap4Byte:
			log.Printf("4byte ASN supported")
			if _, err := io.CopyN(buf, r, int64(msgCap.Length)); err != nil {
				return err
			}
			asn32, err := decode4OctetAS(buf)
			if err != nil {
				return err
			}
			p.ASN32 = asn32
			p.Supported = append(p.Supported, msgCap.Code)

		case capRefresh:
			log.Printf("Route refresh supported")
			p.Refresh = true
			p.Supported = append(p.Supported, msgCap.Code)

		case capMpBgp:
			log.Printf("Multi-protocol BGP supported")
			if _, err := io.CopyN(buf, r, int64(msgCap.Length)); err != nil {
				return err
			}
			a, err := decodeAfiSafi(buf)
			if err != nil {
				return err
			}
			p.AddrFamilies = append(p.AddrFamilies, a)
			p.Supported = append(p.Supported, msgCap.Code)

		case capAddPath:
			log.Printf("BGP Add-Path supported")
			if _, err := io.CopyN(buf, r, int64(msgCap.Length)); err != nil {
				return err
			}
			for buf.Len() > 0 {
				a, err := decodeAddPath(buf)
				if err != nil {
					return err
				}
				p.AddPath = append(p.AddPath, a)
			}
			p.Supported = append(p.Supported, msgCap.Code)

		default:
			log.Printf("Capability %d is not supported", msgCap.Code)
			p.Unsupported = append(p.Unsupported, msgCap.Code)
			if _, err := io.CopyN(io.Discard, r, int64(msgCap.Length)); err != nil {
				return err
			}
		}
	}
	return nil
}

func decode4OctetAS(b *bytes.Buffer) ([4]byte, error) {
	var asn32 [4]byte
	if err := binary.Read(b, binary.BigEndian, &asn32); err != nil {
		return asn32, err
	}
	return asn32, nil
}

func decodeAfiSafi(b *bytes.Buffer) (Addr, error) {
	var a Addr
	if err := binary.Read(b, binary.BigEndian, &a); err != nil {
		return a, err
	}
	return a, nil
}

func decodeAddPath(b *bytes.Buffer) (AddPathCapability, error) {
	var a AddPathCapability
	if err := binary.Read(b, binary.BigEndian, &a); err != nil {
		return a, err
	}
	return a, nil
}
