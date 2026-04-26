//go:build integration
// +build integration

package integration

import (
	"context"
	"testing"
	"time"

	pb "github.com/mellowdrifter/bgpwatch/proto"
	"github.com/stretchr/testify/require"
)

const (
	baseBGPPort  = 10179
	baseGRPCPort = 11179
)

// portPair returns unique ports for a test index
func portPair(idx int) (bgpPort, grpcPort int) {
	return baseBGPPort + idx*2, baseGRPCPort + idx*2
}

func TestSessionEstablishes(t *testing.T) {
	t.Log("Testing BGP session establishment between bgpwatch and GoBGP")
	t.Log("Expected: Session reaches ESTABLISHED and bgpwatch reports 1 active peer")
	bgpPort, grpcPort := portPair(0)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetSystemStats(context.Background(), &pb.Empty{})
		return err == nil && len(resp.PeerStats) == 1
	}, 5*time.Second)
}

func TestAnnounceAndGetTotals(t *testing.T) {
	t.Log("Testing IPv4 prefix announcements and gRPC aggregation")
	t.Log("Expected: GetTotals returns at least 3 IPv4 prefixes and 3 paths")
	bgpPort, grpcPort := portPair(1)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	announceIPv4(t, gobgp, "8.8.8.0", 24, "10.0.0.1", []uint32{64500, 15169})
	announceIPv4(t, gobgp, "1.1.1.0", 24, "10.0.0.1", []uint32{64500, 13335})
	announceIPv4(t, gobgp, "9.9.9.0", 24, "10.0.0.1", []uint32{64500, 36692})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetTotals(context.Background(), &pb.Empty{})
		return err == nil && resp.Ipv4Count >= 3
	}, 10*time.Second)

	resp, err := client.GetTotals(context.Background(), &pb.Empty{})
	require.NoError(t, err)
	require.GreaterOrEqual(t, resp.Ipv4Count, int32(3))
	require.GreaterOrEqual(t, resp.TotalIpv4Paths, int64(3))
}

func TestAnnounceAndLookup(t *testing.T) {
	t.Log("Testing Longest Prefix Match (LPM) and exact-match route queries")
	t.Log("Expected: Correct covering prefix and AS path (with GoBGP prepending) are returned")
	bgpPort, grpcPort := portPair(2)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	announceIPv4(t, gobgp, "8.8.8.0", 24, "10.0.0.1", []uint32{64500, 15169})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: "8.8.8.1"})
		return err == nil && resp.Found
	}, 10*time.Second)

	// LPM test
	resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: "8.8.8.1"})
	require.NoError(t, err)
	require.True(t, resp.Found)
	require.Equal(t, "8.8.8.0/24", resp.Route.Prefix)
	// GoBGP prepends its own AS (64500) to the path
	require.Equal(t, []uint32{64500, 64500, 15169}, resp.Route.AsPath)

	// Exact match test
	resp, err = client.GetRoute(context.Background(), &pb.RouteRequest{Address: "8.8.8.0/24"})
	require.NoError(t, err)
	require.True(t, resp.Found)
	require.Equal(t, "8.8.8.0/24", resp.Route.Prefix)
}

func TestWithdrawal(t *testing.T) {
	t.Log("Testing prefix withdrawal from BGP peer")
	t.Log("Expected: Prefix is removed from RIB and counts decrease")
	bgpPort, grpcPort := portPair(3)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	announceIPv4(t, gobgp, "8.8.8.0", 24, "10.0.0.1", []uint32{64500, 15169})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetTotals(context.Background(), &pb.Empty{})
		return err == nil && resp.Ipv4Count >= 1
	}, 10*time.Second)

	withdrawIPv4(t, gobgp, "8.8.8.0", 24)

	waitForConvergence(t, func() bool {
		resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: "8.8.8.1"})
		return err == nil && !resp.Found
	}, 10*time.Second)
}

func TestGetMasks(t *testing.T) {
	t.Log("Testing prefix length (mask) distribution tracking")
	t.Log("Expected: GetMasks reports correct counts for /8, /16, and /24")
	bgpPort, grpcPort := portPair(4)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	announceIPv4(t, gobgp, "8.8.8.0", 24, "10.0.0.1", []uint32{64500, 15169})
	announceIPv4(t, gobgp, "10.0.0.0", 8, "10.0.0.1", []uint32{64500, 1234})
	announceIPv4(t, gobgp, "172.16.0.0", 16, "10.0.0.1", []uint32{64500, 5678})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetMasks(context.Background(), &pb.Empty{})
		return err == nil && resp.Ipv4Masks[24] >= 1 && resp.Ipv4Masks[8] >= 1 && resp.Ipv4Masks[16] >= 1
	}, 10*time.Second)
}

func TestEoRBlocking(t *testing.T) {
	t.Log("Testing End-of-RIB (EoR) synchronization gating")
	t.Log("Expected: gRPC data calls succeed after initial BGP sync (EoR) is complete")
	bgpPort, grpcPort := portPair(5)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, true) // eor=true
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	client := grpcClient(t, grpcPort)
	
	// GoBGP sends an initial EoR after establishing the session and sending the table dump.
	announceIPv4(t, gobgp, "8.8.8.0", 24, "10.0.0.1", []uint32{64500, 15169})

	// Wait for EoR to be processed and GetTotals to succeed
	waitForConvergence(t, func() bool {
		_, err := client.GetTotals(context.Background(), &pb.Empty{})
		return err == nil
	}, 30*time.Second)
}

func TestAddPath(t *testing.T) {
	t.Log("Testing BGP Add-Path support")
	t.Log("Expected: Multiple paths for the same prefix are correctly stored and returned")
	bgpPort, grpcPort := portPair(6)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, true) // Add-Path enabled
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	// Announce same prefix with different path IDs and AS paths
	announceIPv4WithPathID(t, gobgp, "8.8.8.0", 24, "10.0.0.1", []uint32{64500, 15169}, 1)
	announceIPv4WithPathID(t, gobgp, "8.8.8.0", 24, "10.0.0.2", []uint32{64500, 1234}, 2)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: "8.8.8.0/24"})
		return err == nil && len(resp.Routes) == 2
	}, 10*time.Second)

	resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: "8.8.8.0/24"})
	require.NoError(t, err)
	require.Len(t, resp.Routes, 2)
}

func TestIPv6(t *testing.T) {
	t.Log("Testing IPv6 prefix announcements and lookup")
	t.Log("Expected: IPv6 prefixes are correctly stored and retrieved via gRPC")
	bgpPort, grpcPort := portPair(7)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	// Need a helper for IPv6 announcement
	announceIPv6(t, gobgp, "2001:4860::", 32, "2001:db8::1", []uint32{64500, 15169})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetTotals(context.Background(), &pb.Empty{})
		return err == nil && resp.Ipv6Count >= 1
	}, 10*time.Second)

	resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: "2001:4860::8888"})
	require.NoError(t, err)
	require.True(t, resp.Found)
	require.Equal(t, "2001:4860::/32", resp.Route.Prefix)
}

func TestOriginSearch(t *testing.T) {
	t.Log("Testing route lookup by origin ASN")
	t.Log("Expected: Prefixes originated by a specific ASN are correctly returned")
	bgpPort, grpcPort := portPair(8)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	announceIPv4(t, gobgp, "8.8.8.0", 24, "10.0.0.1", []uint32{64500, 15169})
	announceIPv4(t, gobgp, "1.1.1.0", 24, "10.0.0.1", []uint32{64500, 13335})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetPrefixesByOrigin(context.Background(), &pb.OriginRequest{Asn: 15169})
		return err == nil && len(resp.Prefixes) == 1
	}, 10*time.Second)

	resp, err := client.GetPrefixesByOrigin(context.Background(), &pb.OriginRequest{Asn: 15169})
	require.NoError(t, err)
	require.Len(t, resp.Prefixes, 1)
	require.Equal(t, "8.8.8.0/24", resp.Prefixes[0].Prefix)
}

func TestAsPathRegex(t *testing.T) {
	t.Log("Testing route lookup by AS path regex")
	t.Log("Expected: Routes matching the AS path regex are correctly returned")
	bgpPort, grpcPort := portPair(9)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	announceIPv4(t, gobgp, "8.8.8.0", 24, "10.0.0.1", []uint32{64500, 15169})
	announceIPv4(t, gobgp, "1.1.1.0", 24, "10.0.0.1", []uint32{64500, 13335})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		// GoBGP prepends 64500, so path is ^64500 15169$
		resp, err := client.GetPrefixesByAsPath(context.Background(), &pb.AsPathRequest{Regex: "15169$"})
		return err == nil && len(resp.Routes) == 1
	}, 10*time.Second)

	resp, err := client.GetPrefixesByAsPath(context.Background(), &pb.AsPathRequest{Regex: "15169$"})
	require.NoError(t, err)
	require.Len(t, resp.Routes, 1)
	require.Equal(t, "8.8.8.0/24", resp.Routes[0].Prefix)
}

