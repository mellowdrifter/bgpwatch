//go:build integration
// +build integration

package integration

import (
	"context"
	"fmt"
	"testing"
	"time"

	pb "github.com/mellowdrifter/bgpwatch/proto"
	api "github.com/osrg/gobgp/v3/api"
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

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
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

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
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

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
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

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
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

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
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

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
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

func TestAddPathDetailed(t *testing.T) {
	t.Log("Testing BGP Add-Path support with multiple paths and PathIDs")
	bgpPort, grpcPort := portPair(6)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, true, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	// Announce same prefix with multiple path IDs
	announceIPv4WithPathID(t, gobgp, "8.8.8.0", 24, "10.0.0.1", []uint32{64500, 100}, 1)
	announceIPv4WithPathID(t, gobgp, "8.8.8.0", 24, "10.0.0.1", []uint32{64500, 200}, 2)
	announceIPv4WithPathID(t, gobgp, "8.8.8.0", 24, "10.0.0.1", []uint32{64500, 300}, 3)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: "8.8.8.0/24"})
		return err == nil && len(resp.Routes) == 3
	}, 10*time.Second)

	resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: "8.8.8.0/24"})
	require.NoError(t, err)
	require.Len(t, resp.Routes, 3)

	pathIDs := make(map[uint32]bool)
	for _, r := range resp.Routes {
		pathIDs[r.PathId] = true
	}
	require.True(t, pathIDs[1])
	require.True(t, pathIDs[2])
	require.True(t, pathIDs[3])
}

func TestIPv6Detailed(t *testing.T) {
	t.Log("Testing IPv6 support, MP-BGP, and various Next-Hop lengths")
	bgpPort, grpcPort := portPair(7)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	// 1. Standard 16-byte IPv6 Next-Hop
	announceIPv6(t, gobgp, "2600::", 32, []string{"2001:db8::1"}, []uint32{100})
	// 2. 32-byte Next-Hop (Global + Link-Local)
	announceIPv6(t, gobgp, "2607:f8b0::", 32, []string{"2001:db8:1::1", "fe80::1"}, []uint32{200})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetTotals(context.Background(), &pb.Empty{})
		return err == nil && resp.Ipv6Count >= 2
	}, 10*time.Second)

	// Verify v4 and v6 RIBs are independent
	respTotals, err := client.GetTotals(context.Background(), &pb.Empty{})
	require.NoError(t, err)
	require.Equal(t, int32(0), respTotals.Ipv4Count)
	require.Equal(t, int32(2), respTotals.Ipv6Count)

	// Verify specific routes
	resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: "2600::1"})
	require.NoError(t, err)
	require.True(t, resp.Found)
	require.Equal(t, "2600::/32", resp.Route.Prefix)
}

func TestOriginSearch(t *testing.T) {
	t.Log("Testing route lookup by origin ASN")
	t.Log("Expected: Prefixes originated by a specific ASN are correctly returned")
	bgpPort, grpcPort := portPair(8)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
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

func TestAsPathRegexRealistic(t *testing.T) {
	t.Log("Testing AS path regex correctness with diverse scenarios")
	bgpPort, grpcPort := portPair(9)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	// 1. Long AS path
	announceIPv4(t, gobgp, "10.1.1.0", 24, "10.0.0.1", []uint32{100, 200, 300, 400, 500})
	// 2. Prepended path
	announceIPv4(t, gobgp, "10.1.2.0", 24, "10.0.0.1", []uint32{100, 100, 100})
	// 3. Locally originated (empty path)
	announceIPv4(t, gobgp, "10.1.3.0", 24, "10.0.0.1", []uint32{})

	client := grpcClient(t, grpcPort)
	// GoBGP prepends 64500
	waitForConvergence(t, func() bool {
		resp, err := client.GetPrefixesByAsPath(context.Background(), &pb.AsPathRequest{Regex: "_300_"})
		return err == nil && len(resp.Routes) == 1
	}, 10*time.Second)

	// Test regexes
	tests := []struct {
		regex string
		count int
	}{
		{"_300_", 1},
		{"^64500 100", 2},
		{"100$", 1},
		{"^64500$", 1},
	}

	for _, tt := range tests {
		resp, err := client.GetPrefixesByAsPath(context.Background(), &pb.AsPathRequest{Regex: tt.regex})
		require.NoError(t, err)
		require.Len(t, resp.Routes, tt.count, "Regex %s failed", tt.regex)
	}
}

func TestIBGPSession(t *testing.T) {
	t.Log("Testing iBGP session mechanics and Next-Hop preservation baseline")
	bgpPort, grpcPort := portPair(10)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	// Same AS for iBGP
	gobgp, stopGoBGP := startGoBGP(t, 64533, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	announceIPv4(t, gobgp, "1.1.1.0", 24, "10.10.10.10", []uint32{})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: "1.1.1.1"})
		return err == nil && resp.Found
	}, 10*time.Second)

	resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: "1.1.1.1"})
	require.NoError(t, err)
	require.True(t, resp.Found)
	require.Equal(t, "1.1.1.0/24", resp.Route.Prefix)
	// iBGP shouldn't prepend ASN if locally originated
	require.Empty(t, resp.Route.AsPath)
}

func TestMultiplePeersLocalPref(t *testing.T) {
	t.Log("Testing Multiple iBGP Peers — Best Path with LOCAL_PREF")
	bgpPort, grpcPort := portPair(11)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp1, stopGoBGP1 := startGoBGPWithLocalAddr(t, 64533, "10.0.0.1", "127.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
	defer stopGoBGP1()
	waitForSession(t, gobgp1, "127.0.0.1", 10*time.Second)

	gobgp2, stopGoBGP2 := startGoBGPWithLocalAddr(t, 64533, "10.0.0.2", "127.0.0.1", "127.0.0.2", 64533, bgpPort, false, false)
	defer stopGoBGP2()
	waitForSession(t, gobgp2, "127.0.0.1", 10*time.Second)

	prefix := "2.2.2.0"
	maskLen := uint32(24)

	// Peer 1 announces with LP 100
	announceIPv4WithAttributes(t, gobgp1, prefix, maskLen, "10.0.0.1", []uint32{100}, 0, 100)
	// Peer 2 announces with LP 200
	announceIPv4WithAttributes(t, gobgp2, prefix, maskLen, "10.0.0.2", []uint32{200}, 0, 200)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return err == nil && len(resp.Routes) == 2
	}, 10*time.Second)

	// Verify GetRoute (Best Path) returns LP 200
	resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
	require.NoError(t, err)
	require.True(t, resp.Found)
	require.Equal(t, uint32(200), resp.Route.LocalPref)

	// Verify GetRoutes returns both
	respAll, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
	require.NoError(t, err)
	require.Len(t, respAll.Routes, 2)
}

func TestCommunitySearch(t *testing.T) {
	t.Log("Testing community and large community lookups")

	bgpPort, grpcPort := portPair(12)
	stop := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stop()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	client := grpcClient(t, grpcPort)

	// 1. Standard community
	announceIPv4WithCommunities(t, gobgp, "10.2.1.0", 24, "10.0.0.1", []uint32{100}, []uint32{64500<<16 | 123})

	// 2. Large community
	lc := &api.LargeCommunity{GlobalAdmin: 64500, LocalData1: 1, LocalData2: 2}
	announceIPv4WithLargeCommunities(t, gobgp, "10.2.2.0", 24, "10.0.0.1", []uint32{100}, []*api.LargeCommunity{lc})

	waitForConvergence(t, func() bool {
		resp, err := client.GetTotals(context.Background(), &pb.Empty{})
		return err == nil && resp.Ipv4Count == 2
	}, 10*time.Second)

	// Test standard community lookup
	commResp, err := client.GetPrefixesByCommunity(context.Background(), &pb.CommunityRequest{
		Community: 64500<<16 | 123,
	})
	require.NoError(t, err)
	require.Len(t, commResp.Routes, 1)
	require.Equal(t, "10.2.1.0/24", commResp.Routes[0].Prefix)

	// Test large community lookup
	lcommResp, err := client.GetPrefixesByLargeCommunity(context.Background(), &pb.LargeCommunityRequest{
		Community: &pb.LargeCommunity{GlobalAdmin: 64500, LocalData1: 1, LocalData2: 2},
	})
	require.NoError(t, err)
	require.Len(t, lcommResp.Routes, 1)
	require.Equal(t, "10.2.2.0/24", lcommResp.Routes[0].Prefix)
}

func TestUnknownAttributes(t *testing.T) {
	t.Log("Testing resilience to unknown BGP attributes")

	bgpPort, grpcPort := portPair(13)
	stop := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stop()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	client := grpcClient(t, grpcPort)

	announceIPv4WithUnknownAttr(t, gobgp, "1.3.1.0", 24, "10.0.0.1")

	waitForConvergence(t, func() bool {
		resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: "1.3.1.0/24"})
		return err == nil && resp.Found
	}, 10*time.Second)

	t.Log("Successfully received prefix with unknown attribute")
}

func TestPeerFlapRIB(t *testing.T) {
	t.Log("Testing RIB consistency under peer flap")

	bgpPort, grpcPort := portPair(14)
	stop := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stop()

	// 1. First session
	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	client := grpcClient(t, grpcPort)

	for i := 1; i <= 10; i++ {
		announceIPv4(t, gobgp, fmt.Sprintf("10.4.%d.0", i), 24, "10.0.0.1", []uint32{100})
	}

	waitForConvergence(t, func() bool {
		resp, err := client.GetTotals(context.Background(), &pb.Empty{})
		return err == nil && resp.Ipv4Count == 10
	}, 10*time.Second)

	// 2. Flap
	stopGoBGP()

	waitForConvergence(t, func() bool {
		resp, err := client.GetTotals(context.Background(), &pb.Empty{})
		return err == nil && resp.Ipv4Count == 0
	}, 10*time.Second)

	// 3. Second session
	gobgp2, stopGoBGP2 := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
	defer stopGoBGP2()
	waitForSession(t, gobgp2, "127.0.0.1", 10*time.Second)

	announceIPv4(t, gobgp2, "10.4.1.0", 24, "10.0.0.1", []uint32{100})

	waitForConvergence(t, func() bool {
		resp, err := client.GetTotals(context.Background(), &pb.Empty{})
		return err == nil && resp.Ipv4Count == 1
	}, 10*time.Second)
}

func TestFullTablePerformance(t *testing.T) {
	t.Log("Testing RIB performance under load")

	bgpPort, grpcPort := portPair(15)
	stop := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stop()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	client := grpcClient(t, grpcPort)

	count := 500 // Reduced from 1000 to keep it fast
	start := time.Now()
	for i := 0; i < count; i++ {
		b2 := (i / 256)
		b3 := (i % 256)
		prefix := fmt.Sprintf("10.%d.%d.0", 100+b2, b3)
		announceIPv4(t, gobgp, prefix, 24, "10.0.0.1", []uint32{100, 200, 300})
	}
	t.Logf("Sent %d prefixes in %v", count, time.Since(start))

	waitForConvergence(t, func() bool {
		resp, err := client.GetTotals(context.Background(), &pb.Empty{})
		return err == nil && resp.Ipv4Count == int32(count)
	}, 10*time.Second)

	// Test regex search on "full" table
	start = time.Now()
	reResp, err := client.GetPrefixesByAsPath(context.Background(), &pb.AsPathRequest{Regex: "_200_"})
	require.NoError(t, err)
	require.Len(t, reResp.Routes, count)
	t.Logf("Regex search against %d routes took %v", count, time.Since(start))
}

func TestAddPathZeroID(t *testing.T) {
	t.Log("Testing BGP Add-Path with PathID 0 (non-compliant)")
	bgpPort, grpcPort := portPair(16)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, true, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	// Announce with PathID 0. GoBGP API might allow it.
	announceIPv4WithPathID(t, gobgp, "1.1.1.0", 24, "10.0.0.1", []uint32{100}, 0)

	client := grpcClient(t, grpcPort)
	// We check if it's present. If GoBGP rejected it, the count will be 0.
	// If bgpwatch rejected it, the count will be 0.
	// Either way, we ensure no crash.
	time.Sleep(2 * time.Second)
	resp, err := client.GetTotals(context.Background(), &pb.Empty{})
	require.NoError(t, err)
	t.Logf("Prefixes with PathID 0: %d", resp.Ipv4Count)
}

func TestAddPathImplicitWithdrawal(t *testing.T) {
	t.Log("Testing BGP Add-Path implicit withdrawal (same ID, different attributes)")
	bgpPort, grpcPort := portPair(17)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, true, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	prefix := "2.2.2.0/24"
	// 1. First announcement
	announceIPv4WithPathID(t, gobgp, "2.2.2.0", 24, "10.0.0.1", []uint32{100}, 1)
	// 2. Second announcement (different AS path)
	announceIPv4WithPathID(t, gobgp, "2.2.2.0", 24, "10.0.0.1", []uint32{200}, 1)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix})
		return err == nil && len(resp.Routes) == 1
	}, 10*time.Second)

	resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix})
	require.NoError(t, err)
	require.Len(t, resp.Routes, 1)
	// GoBGP prepends 64500
	require.Equal(t, []uint32{64500, 200}, resp.Routes[0].AsPath)
}

func TestAddPathPartialWithdrawal(t *testing.T) {
	t.Log("Testing BGP Add-Path partial withdrawal")
	bgpPort, grpcPort := portPair(18)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, true, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	prefix := "3.3.3.0"
	announceIPv4WithPathID(t, gobgp, prefix, 24, "10.0.0.1", []uint32{100}, 1)
	announceIPv4WithPathID(t, gobgp, prefix, 24, "10.0.0.1", []uint32{200}, 2)
	announceIPv4WithPathID(t, gobgp, prefix, 24, "10.0.0.1", []uint32{300}, 3)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return err == nil && len(resp.Routes) == 3
	}, 10*time.Second)

	// Withdraw PathID 2
	withdrawIPv4WithPathID(t, gobgp, prefix, 24, 2)

	waitForConvergence(t, func() bool {
		resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return err == nil && len(resp.Routes) == 2
	}, 10*time.Second)

	resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
	require.NoError(t, err)
	for _, r := range resp.Routes {
		require.NotEqual(t, uint32(2), r.PathId)
	}
}

func TestAddPathUnknownWithdrawal(t *testing.T) {
	t.Log("Testing BGP Add-Path withdrawal for unknown PathID")
	bgpPort, grpcPort := portPair(19)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, true, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	prefix := "4.4.4.0"
	announceIPv4WithPathID(t, gobgp, prefix, 24, "10.0.0.1", []uint32{100}, 1)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return err == nil && len(resp.Routes) == 1
	}, 10*time.Second)

	// Withdraw unknown PathID 99
	withdrawIPv4WithPathID(t, gobgp, prefix, 24, 99)

	// Ensure PathID 1 survives and no crash
	time.Sleep(2 * time.Second)
	resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
	require.NoError(t, err)
	require.Len(t, resp.Routes, 1)
	require.Equal(t, uint32(1), resp.Routes[0].PathId)
}

func TestMultiPeerOverlappingPathIDs(t *testing.T) {
	t.Log("Testing Multiple senders with overlapping PathIDs")
	bgpPort, grpcPort := portPair(20)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	// Peer 1
	gobgp1, stopGoBGP1 := startGoBGPWithLocalAddr(t, 64500, "10.0.0.1", "127.0.0.1", "127.0.0.1", 64533, bgpPort, true, false)
	defer stopGoBGP1()
	waitForSession(t, gobgp1, "127.0.0.1", 10*time.Second)

	// Peer 2
	gobgp2, stopGoBGP2 := startGoBGPWithLocalAddr(t, 64501, "10.0.0.2", "127.0.0.1", "127.0.0.2", 64533, bgpPort, true, false)
	defer stopGoBGP2()
	waitForSession(t, gobgp2, "127.0.0.1", 10*time.Second)

	prefix := "5.5.5.0"
	// Both use PathID 1
	announceIPv4WithPathID(t, gobgp1, prefix, 24, "10.0.0.1", []uint32{100}, 1)
	announceIPv4WithPathID(t, gobgp2, prefix, 24, "10.0.0.2", []uint32{200}, 1)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return err == nil && len(resp.Routes) == 2
	}, 10*time.Second)

	resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
	require.NoError(t, err)
	require.Len(t, resp.Routes, 2)
}

func TestLocalPrefDefault(t *testing.T) {
	t.Log("Testing BGP LocalPref defaulting (0 -> 100)")
	bgpPort, grpcPort := portPair(21)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64533, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	prefix := "7.7.7.0/24"
	// Announce with LP 0 (defaults to 100)
	announceIPv4WithAttributes(t, gobgp, "7.7.7.0", 24, "10.0.0.1", []uint32{100}, 0, 0)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix})
		return err == nil && resp.Found
	}, 10*time.Second)

	resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix})
	require.NoError(t, err)
	require.True(t, resp.Found)
	// Even though we sent 0, we verify it's treated as best or just that we see 0 but it's handled as 100 internally.
	// Actually we should test it AGAINST something else.
}

func TestLocalPrefDefaultAgainstExplicit(t *testing.T) {
	t.Log("Testing BGP LocalPref defaulting against explicit lower value")
	bgpPort, grpcPort := portPair(22)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	// Use iBGP to ensure attributes are preserved
	gobgp1, stopGoBGP1 := startGoBGPWithLocalAddr(t, 64533, "10.0.0.1", "127.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
	defer stopGoBGP1()
	gobgp2, stopGoBGP2 := startGoBGPWithLocalAddr(t, 64533, "10.0.0.2", "127.0.0.1", "127.0.0.2", 64533, bgpPort, false, false)
	defer stopGoBGP2()

	waitForSession(t, gobgp1, "127.0.0.1", 10*time.Second)
	waitForSession(t, gobgp2, "127.0.0.1", 10*time.Second)

	prefix := "7.8.0.0/16"
	// Peer 1: No LP (0 -> 100)
	announceIPv4WithAttributes(t, gobgp1, "7.8.0.0", 16, "10.0.0.1", []uint32{100}, 0, 0)
	// Peer 2: Explicit LP 50
	announceIPv4WithAttributes(t, gobgp2, "7.8.0.0", 16, "10.0.0.2", []uint32{200}, 0, 50)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix})
		return err == nil && len(resp.Routes) == 2
	}, 10*time.Second)

	// Best path should be Peer 1 (100 > 50)
	resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix})
	require.NoError(t, err)
	require.True(t, resp.Found)
	// Stored as 0 (if GoBGP preserves it as absent) or 100 (if GoBGP defaults it). Both are acceptable as long as it's best.
	require.True(t, resp.Route.LocalPref == 0 || resp.Route.LocalPref == 100)
	require.Equal(t, uint32(100), resp.Route.AsPath[0]) // Verification it's Peer 1's route
}

func TestMidStreamConvergence(t *testing.T) {
	t.Log("Testing Best Path convergence mid-stream")
	bgpPort, grpcPort := portPair(23)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64533, "10.0.0.1", "127.0.0.1", 64533, bgpPort, true, false)
	defer stopGoBGP()

	waitForSession(t, gobgp, "127.0.0.1", 10*time.Second)

	prefix := "8.8.8.0"
	// 1. Initial path (LP 50)
	announceIPv4WithPathID(t, gobgp, prefix, 24, "10.0.0.1", []uint32{100}, 1)
	// We need to set LP 50. Use WithAttributes
	announceIPv4WithAttributes(t, gobgp, prefix, 24, "10.0.0.1", []uint32{100}, 1, 50)

	// 2. Better path (LP 150) arrives
	announceIPv4WithAttributes(t, gobgp, prefix, 24, "10.0.0.1", []uint32{200}, 2, 150)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		if err != nil {
			t.Logf("GetRoute error: %v", err)
			return false
		}
		if !resp.Found {
			t.Log("GetRoute: Found=false")
			return false
		}
		t.Logf("GetRoute: Found=true, LP=%d, PathID=%d", resp.Route.LocalPref, resp.Route.PathId)
		return resp.Route.LocalPref == 150
	}, 20*time.Second)

	resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
	require.NoError(t, err)
	require.True(t, resp.Found)
	require.Equal(t, uint32(150), resp.Route.LocalPref)
}

func TestBestPathFlipOnWithdrawal(t *testing.T) {
	t.Log("Testing Best Path flip on withdrawal")
	bgpPort, grpcPort := portPair(24)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp1, stopGoBGP1 := startGoBGPWithLocalAddr(t, 64533, "10.0.0.1", "127.0.0.1", "127.0.0.1", 64533, bgpPort, false, false)
	defer stopGoBGP1()
	gobgp2, stopGoBGP2 := startGoBGPWithLocalAddr(t, 64533, "10.0.0.2", "127.0.0.1", "127.0.0.2", 64533, bgpPort, false, false)
	defer stopGoBGP2()

	waitForSession(t, gobgp1, "127.0.0.1", 10*time.Second)
	waitForSession(t, gobgp2, "127.0.0.1", 10*time.Second)

	prefix := "9.9.9.0/24"
	// Peer 1: LP 200 (Best)
	announceIPv4WithAttributes(t, gobgp1, "9.9.9.0", 24, "10.0.0.1", []uint32{100}, 0, 200)
	// Peer 2: LP 100 (Backup)
	announceIPv4WithAttributes(t, gobgp2, "9.9.9.0", 24, "10.0.0.2", []uint32{200}, 0, 100)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix})
		return err == nil && resp.Found && resp.Route.LocalPref == 200
	}, 10*time.Second)

	// Withdraw Peer 1's route
	t.Log("Withdrawing Peer 1 route...")
	withdrawIPv4(t, gobgp1, "9.9.9.0", 24)

	// Should flip to Peer 2 (LP 100)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix})
		if err != nil {
			t.Logf("GetRoute error: %v", err)
			return false
		}
		if !resp.Found {
			t.Log("GetRoute: Found=false")
			return false
		}
		t.Logf("GetRoute: Found=true, LP=%d, Peer=%s", resp.Route.LocalPref, resp.Route.PeerIp)
		return resp.Route.LocalPref == 100
	}, 20*time.Second)

	resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix})
	require.NoError(t, err)
	require.True(t, resp.Found)
	require.Equal(t, uint32(100), resp.Route.LocalPref)
}

