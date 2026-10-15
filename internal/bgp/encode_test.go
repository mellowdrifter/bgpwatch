package bgp

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

func TestCreateOpenGracefulRestart(t *testing.T) {
	rid := BGPID{1, 1, 1, 1}

	t.Run("IPv4 only", func(t *testing.T) {
		p := &Parameters{
			AddrFamilies: []Addr{{AFI: 1, SAFI: 1}},
		}
		msg := CreateOpen(64500, 90, rid, p)
		params := msg[29:]
		decoded, err := DecodeOptionalParameters(&params)
		if err != nil {
			t.Fatalf("DecodeOptionalParameters failed: %v", err)
		}
		if decoded.GRCapability == nil {
			t.Fatal("expected GRCapability to be decoded, got nil")
		}
		if len(decoded.GRCapability.AFIs) != 1 {
			t.Fatalf("expected 1 GR family, got %d", len(decoded.GRCapability.AFIs))
		}
		if decoded.GRCapability.AFIs[0].AFI != 1 || decoded.GRCapability.AFIs[0].SAFI != 1 {
			t.Errorf("expected IPv4 Unicast GR, got %+v", decoded.GRCapability.AFIs[0])
		}
	})

	t.Run("IPv6 only", func(t *testing.T) {
		p := &Parameters{
			AddrFamilies: []Addr{{AFI: 2, SAFI: 1}},
		}
		msg := CreateOpen(64500, 90, rid, p)
		params := msg[29:]
		decoded, err := DecodeOptionalParameters(&params)
		if err != nil {
			t.Fatalf("DecodeOptionalParameters failed: %v", err)
		}
		if decoded.GRCapability == nil {
			t.Fatal("expected GRCapability to be decoded, got nil")
		}
		if len(decoded.GRCapability.AFIs) != 1 {
			t.Fatalf("expected 1 GR family, got %d", len(decoded.GRCapability.AFIs))
		}
		if decoded.GRCapability.AFIs[0].AFI != 2 || decoded.GRCapability.AFIs[0].SAFI != 1 {
			t.Errorf("expected IPv6 Unicast GR, got %+v", decoded.GRCapability.AFIs[0])
		}
	})

	t.Run("Dual Stack", func(t *testing.T) {
		p := &Parameters{
			AddrFamilies: []Addr{
				{AFI: 1, SAFI: 1},
				{AFI: 2, SAFI: 1},
			},
		}
		msg := CreateOpen(64500, 90, rid, p)
		params := msg[29:]
		decoded, err := DecodeOptionalParameters(&params)
		if err != nil {
			t.Fatalf("DecodeOptionalParameters failed: %v", err)
		}
		if decoded.GRCapability == nil {
			t.Fatal("expected GRCapability to be decoded, got nil")
		}
		if len(decoded.GRCapability.AFIs) != 2 {
			t.Fatalf("expected 2 GR families, got %d", len(decoded.GRCapability.AFIs))
		}
		if decoded.GRCapability.AFIs[0].AFI != 1 || decoded.GRCapability.AFIs[0].SAFI != 1 {
			t.Errorf("expected IPv4 Unicast GR as first family, got %+v", decoded.GRCapability.AFIs[0])
		}
		if decoded.GRCapability.AFIs[1].AFI != 2 || decoded.GRCapability.AFIs[1].SAFI != 1 {
			t.Errorf("expected IPv6 Unicast GR as second family, got %+v", decoded.GRCapability.AFIs[1])
		}
	})
}

