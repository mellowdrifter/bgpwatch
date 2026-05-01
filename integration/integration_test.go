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

func TestAddPathDetailed(t *testing.T) {
	t.Log("Testing BGP Add-Path support with multiple paths and PathIDs")
	bgpPort, grpcPort := portPair(6)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, true)
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

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
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

func TestAsPathRegexRealistic(t *testing.T) {
	t.Log("Testing AS path regex correctness with diverse scenarios")
	bgpPort, grpcPort := portPair(9)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
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
	gobgp, stopGoBGP := startGoBGP(t, 64533, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
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

	gobgp1, stopGoBGP1 := startGoBGPWithLocalAddr(t, 64533, "10.0.0.1", "127.0.0.1", "127.0.0.1", 64533, bgpPort, false)
	defer stopGoBGP1()
	waitForSession(t, gobgp1, "127.0.0.1", 10*time.Second)

	gobgp2, stopGoBGP2 := startGoBGPWithLocalAddr(t, 64533, "10.0.0.2", "127.0.0.1", "127.0.0.2", 64533, bgpPort, false)
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

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
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

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
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
	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
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
	gobgp2, stopGoBGP2 := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
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

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false)
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

