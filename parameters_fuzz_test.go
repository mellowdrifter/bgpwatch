package main

import (
	"testing"
)

func FuzzDecodeOptionalParameters(f *testing.F) {
	f.Add([]byte{0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01}) // MP-BGP Capability
	
	f.Fuzz(func(t *testing.T, data []byte) {
		_, _ = decodeOptionalParameters(&data)
	})
}

func FuzzDecodeCapability(f *testing.F) {
	f.Add([]byte{0x01, 0x04, 0x00, 0x01, 0x00, 0x01}) // MP-BGP
	f.Add([]byte{0x41, 0x04, 0x00, 0x00, 0x03, 0xe8}) // 4-byte ASN (1000)
	
	f.Fuzz(func(t *testing.T, data []byte) {
		var p parameters
		_ = decodeCapability(data, &p)
	})
}
