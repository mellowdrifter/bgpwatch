package server

import (
	"context"
	"net/netip"
	"sort"
	"testing"

	"github.com/google/go-cmp/cmp"
	"github.com/mellowdrifter/bgpwatch/internal/bgp"
	pb "github.com/mellowdrifter/bgpwatch/proto"
	"github.com/mellowdrifter/routing_table"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestGetInvalidPrefixes(t *testing.T) {
	s := New(Config{})
	grpcSrv := &grpcServer{bgp: s}

	v4rib1 := routing_table.NewIPv4Rib(s.v4AttrTable)
	v6rib1 := routing_table.NewIPv6Rib(s.v6AttrTable)

	// Peer 1 announcements
	// Invalid IPv4 route (LocalPref = 50) originated by AS15169
	v4rib1.Insert(routing_table.Route{
		Prefix: netip.MustParsePrefix("11.1.1.0/24"),
		Attributes: &routing_table.RouteAttributes{
			LocalPref: 50,
			AsPath:    []uint32{64500, 15169},
		},
	})
	// Valid IPv4 route (LocalPref = 100) originated by AS15169
	v4rib1.Insert(routing_table.Route{
		Prefix: netip.MustParsePrefix("11.1.2.0/24"),
		Attributes: &routing_table.RouteAttributes{
			LocalPref: 100,
			AsPath:    []uint32{64500, 15169},
		},
	})
	// Invalid IPv6 route (LocalPref = 50) originated by AS13335
	v6rib1.Insert(routing_table.Route{
		Prefix: netip.MustParsePrefix("2001:db8:1::/48"),
		Attributes: &routing_table.RouteAttributes{
			LocalPref: 50,
			AsPath:    []uint32{64500, 13335},
		},
	})
	// Valid IPv6 route (LocalPref = 200) originated by AS13335
	v6rib1.Insert(routing_table.Route{
		Prefix: netip.MustParsePrefix("2001:db8:2::/48"),
		Attributes: &routing_table.RouteAttributes{
			LocalPref: 200,
			AsPath:    []uint32{64500, 13335},
		},
	})

	// Peer 2 announcements (testing deduplication across peers)
	v4rib2 := routing_table.NewIPv4Rib(s.v4AttrTable)
	// Duplicate announcement of 11.1.1.0/24 with LocalPref = 50
	v4rib2.Insert(routing_table.Route{
		Prefix: netip.MustParsePrefix("11.1.1.0/24"),
		Attributes: &routing_table.RouteAttributes{
			LocalPref: 50,
			AsPath:    []uint32{64501, 15169},
		},
	})
	// Another invalid prefix from AS13335
	v4rib2.Insert(routing_table.Route{
		Prefix: netip.MustParsePrefix("11.2.1.0/24"),
		Attributes: &routing_table.RouteAttributes{
			LocalPref: 50,
			AsPath:    []uint32{64501, 13335},
		},
	})

	p1 := &peer{
		ip:    "192.0.2.1",
		v4rib: v4rib1,
		v6rib: v6rib1,
	}
	p1.status.Store(uint32(StatusEstablished))

	p2 := &peer{
		ip:    "192.0.2.2",
		v4rib: v4rib2,
	}
	p2.status.Store(uint32(StatusEstablished))

	s.peers = []*peer{p1, p2}

	ctx := context.Background()

	t.Run("Global Query (asn == 0)", func(t *testing.T) {
		resp, err := grpcSrv.GetInvalidPrefixes(ctx, &pb.OriginRequest{Asn: 0})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var got []string
		for _, p := range resp.GetPrefixes() {
			got = append(got, p.GetPrefix())
		}
		sort.Strings(got)

		want := []string{"11.1.1.0/24", "11.2.1.0/24", "2001:db8:1::/48"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("GetInvalidPrefixes(0) mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("Filter by Origin ASN 15169", func(t *testing.T) {
		resp, err := grpcSrv.GetInvalidPrefixes(ctx, &pb.OriginRequest{Asn: 15169})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var got []string
		for _, p := range resp.GetPrefixes() {
			got = append(got, p.GetPrefix())
		}
		sort.Strings(got)

		want := []string{"11.1.1.0/24"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("GetInvalidPrefixes(15169) mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("Filter by Origin ASN 13335", func(t *testing.T) {
		resp, err := grpcSrv.GetInvalidPrefixes(ctx, &pb.OriginRequest{Asn: 13335})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		var got []string
		for _, p := range resp.GetPrefixes() {
			got = append(got, p.GetPrefix())
		}
		sort.Strings(got)

		want := []string{"11.2.1.0/24", "2001:db8:1::/48"}
		if diff := cmp.Diff(want, got); diff != "" {
			t.Errorf("GetInvalidPrefixes(13335) mismatch (-want +got):\n%s", diff)
		}
	})

	t.Run("Filter by Origin ASN with no invalid prefixes", func(t *testing.T) {
		resp, err := grpcSrv.GetInvalidPrefixes(ctx, &pb.OriginRequest{Asn: 36692})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.GetPrefixes()) != 0 {
			t.Errorf("expected 0 prefixes, got %d", len(resp.GetPrefixes()))
		}
	})

	t.Run("Invalid Bogon ASN", func(t *testing.T) {
		_, err := grpcSrv.GetInvalidPrefixes(ctx, &pb.OriginRequest{Asn: 64512})
		if err == nil {
			t.Fatal("expected error for private ASN 64512, got nil")
		}
		st, ok := status.FromError(err)
		if !ok || st.Code() != codes.InvalidArgument {
			t.Errorf("expected InvalidArgument code, got: %v", err)
		}
	})

	t.Run("Nil Request Defaults to Global Scan", func(t *testing.T) {
		resp, err := grpcSrv.GetInvalidPrefixes(ctx, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if len(resp.GetPrefixes()) != 3 {
			t.Errorf("expected 3 prefixes for nil request, got %d", len(resp.GetPrefixes()))
		}
	})
}

func TestGetInvalidPrefixesAddPath(t *testing.T) {
	s := New(Config{})
	grpcSrv := &grpcServer{bgp: s}

	v4rib := routing_table.NewIPv4Rib(s.v4AttrTable)

	// AddPath: Best path has LP=100, but alternate path ID 2 has LP=50
	v4rib.Insert(routing_table.Route{
		Prefix: netip.MustParsePrefix("11.3.1.0/24"),
		Attributes: &routing_table.RouteAttributes{
			LocalPref: 100,
			AsPath:    []uint32{64500, 15169},
		},
		PathID: 1,
	})
	v4rib.Insert(routing_table.Route{
		Prefix: netip.MustParsePrefix("11.3.1.0/24"),
		Attributes: &routing_table.RouteAttributes{
			LocalPref: 50,
			AsPath:    []uint32{64500, 15169},
		},
		PathID: 2,
	})

	p := &peer{
		ip:    "192.0.2.1",
		v4rib: v4rib,
	}
	p.param.AddPath = []bgp.AddPathCapability{
		{AFI: 1, SAFI: 1, SendReceive: 3},
	}
	p.status.Store(uint32(StatusEstablished))
	s.peers = []*peer{p}

	// 1. Global query should find it via AddPath scan
	resp, err := grpcSrv.GetInvalidPrefixes(context.Background(), &pb.OriginRequest{Asn: 0})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(resp.GetPrefixes()) != 1 || resp.GetPrefixes()[0].GetPrefix() != "11.3.1.0/24" {
		t.Fatalf("expected 11.3.1.0/24, got %v", resp.GetPrefixes())
	}

	// 2. ASN filter should also find it
	respASN, err := grpcSrv.GetInvalidPrefixes(context.Background(), &pb.OriginRequest{Asn: 15169})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(respASN.GetPrefixes()) != 1 || respASN.GetPrefixes()[0].GetPrefix() != "11.3.1.0/24" {
		t.Fatalf("expected 11.3.1.0/24, got %v", respASN.GetPrefixes())
	}
}

func TestGetInvalidPrefixesDaemonBusy(t *testing.T) {
	s := New(Config{})
	grpcSrv := &grpcServer{bgp: s}

	p := &peer{
		ip:   "192.0.2.1",
		weor: true,
	}
	s.peers = []*peer{p}

	_, err := grpcSrv.GetInvalidPrefixes(context.Background(), &pb.OriginRequest{Asn: 0})
	if err == nil {
		t.Fatal("expected error when daemon is waiting for EoR, got nil")
	}
	st, ok := status.FromError(err)
	if !ok || st.Code() != codes.Unavailable {
		t.Errorf("expected Unavailable code, got: %v", err)
	}
}
