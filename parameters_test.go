package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestDecodeOptionalParameters(t *testing.T) {
	tests := []struct {
		desc  string
		input []byte
		want  parameters
	}{
		{
			desc: "All capabilities under a single capability field",
			input: []byte{
				0x02, 0x16, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x00, 0x40, 0x02,
				0x00, 0x78, 0x41, 0x04, 0x00, 0x00, 0xfc, 0x15, 0x46, 0x00, 0x47, 0x00,
			},
			want: parameters{
				ASN32:   0,
				Refresh: true,
				AddrFamilies: []addr{
					addr{
						AFI:  0,
						SAFI: 0,
					},
				},
				Supported:   []uint8{1, 65, 70},
				Unsupported: []uint8{2, 64, 71},
			},
		},
		{
			desc: "All capabilities under seperate capability fields",
			// This has both 2 and 128 - route refresh and Cisco route refresh. Should I consider that refresh == 2 ?
			input: []byte{
				0x02, 0x06, 0x01, 0x04, 0x00, 0x01, 0x00, 0x01, 0x02, 0x02, 0x80, 0x00,
				0x02, 0x02, 0x02, 0x00,
			},
			want: parameters{
				ASN32:   0,
				Refresh: false,
				AddrFamilies: []addr{
					addr{
						AFI:  0,
						SAFI: 0,
					},
				},
				Supported:   []uint8{1},
				Unsupported: []uint8{128, 2},
			},
		},
	}
	for _, test := range tests {
		got := decodeOptionalParameters(&test.input)

		if !cmp.Equal(got, test.want) {
			t.Errorf("Test (%s): got %+v, want %+v", test.desc, got, test.want)
		}
	}
}
