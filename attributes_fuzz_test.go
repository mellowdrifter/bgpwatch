package main

import (
	"bytes"
	"testing"
)

func FuzzDecodePathAttributes(f *testing.F) {
	// Add some seed corpus
	f.Add([]byte{0x40, 0x01, 0x01, 0x00}, false) // Origin IGP
	f.Add([]byte{0x40, 0x02, 0x04, 0x02, 0x01, 0x00, 0x00, 0x00, 0x64}, false) // AS Path [100]
	
	f.Fuzz(func(t *testing.T, data []byte, ignoreComms bool) {
		// We don't care about the result, only that it doesn't panic
		_, _ = decodePathAttributes(data, nil, ignoreComms)
	})
}

func FuzzDecodeIPv4Withdraws(f *testing.F) {
	f.Add([]byte{24, 192, 168, 1})
	f.Add([]byte{32, 8, 8, 8, 8})
	
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeIPv4Withdraws(data, nil)
	})
}

func FuzzDecodeIPv4NLRI(f *testing.F) {
	f.Add([]byte{24, 192, 168, 1})
	
	f.Fuzz(func(t *testing.T, data []byte) {
		r := bytes.NewReader(data)
		_, _ = decodeIPv4NLRI(r, nil)
	})
}

func FuzzDecodeIPv6NLRI(f *testing.F) {
	f.Add([]byte{64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0})
	
	f.Fuzz(func(t *testing.T, data []byte) {
		buf := bytes.NewBuffer(data)
		_, _ = decodeIPv6NLRI(buf, nil)
	})
}

func FuzzDecodeMPReachNLRI(f *testing.F) {
	// AFI=2 (IPv6), SAFI=1 (Unicast), NH Len=16, NH=::1, Reserved=0, Prefix=64 2001:db8::
	f.Add([]byte{0, 2, 1, 16, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0})
	
	f.Fuzz(func(t *testing.T, data []byte) {
		buf := bytes.NewBuffer(data)
		_, _, _ = decodeMPReachNLRI(buf, nil)
	})
}

func FuzzDecodeMPUnreachNLRI(f *testing.F) {
	// AFI=2, SAFI=1, Prefix=64 2001:db8::
	f.Add([]byte{0, 2, 1, 64, 0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0})
	
	f.Fuzz(func(t *testing.T, data []byte) {
		buf := bytes.NewBuffer(data)
		_, _, _ = decodeMPUnreachNLRI(buf, int64(len(data)), nil)
	})
}
