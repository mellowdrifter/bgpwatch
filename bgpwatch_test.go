package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestGetRid(t *testing.T) {
	tests := []struct {
		desc    string
		srid    string
		wantErr bool
		want    bgpid
	}{
		{
			desc:    "empty",
			wantErr: true,
		},
		{
			desc:    "wrong format",
			srid:    "1.1.1.1.1",
			wantErr: true,
		},
		{
			desc:    "wrong format - IPv6",
			srid:    "2001::db8",
			wantErr: true,
		},
		{
			desc:    "wrong format - letter",
			srid:    "0.0.0.a",
			wantErr: true,
		},
		{
			desc: "default RID",
			srid: "0.0.0.1",
			want: bgpid{0x0, 0x0, 0x0, 0x1},
		},
		{
			desc: "regular RID",
			srid: "9.8.7.6",
			want: bgpid{0x9, 0x8, 0x7, 0x6},
		},
		{
			desc: "max RID",
			srid: "255.255.255.255",
			want: bgpid{0xff, 0xff, 0xff, 0xff},
		},
	}
	for _, test := range tests {
		got, err := getRid(&test.srid)
		if test.wantErr {
			if err == nil {
				t.Errorf("Test (%s): wanted error but none received", test.desc)
			}
		}

		if !cmp.Equal(got, test.want) {
			t.Errorf("Test (%s): got %#v, want %#v", test.desc, got, test.want)
		}
	}
}
