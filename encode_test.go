package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestUint16ToByte(t *testing.T) {
	tests := []struct {
		desc  string
		input uint16
		want  []byte
	}{
		{
			desc:  "test1",
			input: 64500,
			want:  []byte{0xfb, 0xf4},
		},
	}
	for _, test := range tests {
		got := uint16ToByte(test.input)

		if !cmp.Equal(got, test.want) {
			t.Errorf("Test (%s): got %#v, want %#v", test.desc, got, test.want)
		}
	}
}

func TestUint32ToByte(t *testing.T) {
	tests := []struct {
		desc  string
		input uint32
		want  []byte
	}{
		{
			desc:  "test1",
			input: 2621441,
			want:  []byte{0x0, 0x28, 0x00, 0x01},
		},
	}
	for _, test := range tests {
		got := uint32ToByte(test.input)

		if !cmp.Equal(got, test.want) {
			t.Errorf("Test (%s): got %#v, want %#v", test.desc, got, test.want)
		}
	}
}
