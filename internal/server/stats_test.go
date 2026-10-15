package server

import (
	"net/netip"
	"testing"

	"github.com/mellowdrifter/routing_table"
)

func TestCollectStatsDualStack(t *testing.T) {
	s := New(Config{})

	v4rib := routing_table.NewIPv4Rib(s.v4AttrTable)
	v6rib := routing_table.NewIPv6Rib(s.v6AttrTable)

	attrs := &routing_table.RouteAttributes{
		LocalPref: 100,
		AsPath:    []uint32{64500, 15169},
	}

	v4rib.Insert(routing_table.Route{
		Prefix:     netip.MustParsePrefix("192.0.2.0/24"),
		Attributes: attrs,
	})
	v6rib.Insert(routing_table.Route{
		Prefix:     netip.MustParsePrefix("2001:db8::/32"),
		Attributes: attrs,
	})

	p := &peer{
		ip:    "192.0.2.1",
		v4rib: v4rib,
		v6rib: v6rib,
	}
	p.status.Store(uint32(StatusEstablished))

	s.peers = []*peer{p}

	stats := s.collectStats()

	peerName := s.getPeerName(p)
	ps, ok := stats.PeerStats[peerName]
	if !ok {
		t.Fatalf("expected stats for peer %s", peerName)
	}

	if ps.PrefixCount != 2 {
		t.Errorf("PrefixCount = %d, want 2 (1 v4 + 1 v6)", ps.PrefixCount)
	}

	if ps.PathCount != 2 {
		t.Errorf("PathCount = %d, want 2 (1 v4 + 1 v6)", ps.PathCount)
	}

	if ps.RibRamBytes == 0 {
		t.Errorf("RibRamBytes should be > 0")
	}

	if stats.TotalPeerRibRamBytes == 0 {
		t.Errorf("TotalPeerRibRamBytes should be > 0")
	}
}
