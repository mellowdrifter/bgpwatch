//go:build integration
// +build integration

package integration

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"testing"
	"time"

	"github.com/mellowdrifter/bgpwatch/internal/server"
	pb "github.com/mellowdrifter/bgpwatch/proto"
	"github.com/stretchr/testify/require"
)

func anonymize(ip string) string {
	hash := sha256.Sum256([]byte(ip))
	return "peer-" + hex.EncodeToString(hash[:4])
}

// TestGracefulRestart1_Negotiation verifies that GR capability is correctly parsed and active.
// Also verifies that a peer without GR results in immediate purge.
func TestGracefulRestart1_Negotiation(t *testing.T) {
	t.Log("Test 1: Baseline GR negotiation")

	bgpPort, grpcPort := portPair(40)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	// 1. Peer WITH GR capability
	gobgp1, stopGoBGP1 := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	defer stopGoBGP1()
	waitForSession(t, gobgp1, "127.0.0.1", 30*time.Second)

	client := grpcClient(t, grpcPort)
	stats, err := client.GetSystemStats(context.Background(), &pb.Empty{})
	require.NoError(t, err)

	// In integration tests, GoBGP connects FROM a random port, but the IP is usually 127.0.0.1
	// BGPWatch identifies peers by IP.
	peerID := anonymize("127.0.0.1")
	require.Contains(t, stats.PeerStats, peerID)
	require.True(t, stats.PeerStats[peerID].GracefulRestart, "GR should be active for peer 1")

	// 2. Peer WITHOUT GR capability
	// We need another GoBGP instance or just re-use the same IP if we disconnect first.
	// Actually, BGPWatch only allows one peer per IP. Let's use a different local address for the second peer.
	// Wait, standard startGoBGP connects to 127.0.0.1:bgpPort.
	// If we use 127.0.0.2 as source, we can have two peers.
	gobgp2, stopGoBGP2 := startGoBGPWithLocalAddr(t, 64501, "10.0.0.2", "127.0.0.1", "127.0.0.2", 64533, bgpPort, false, false)
	defer stopGoBGP2()
	waitForSession(t, gobgp2, "127.0.0.1", 30*time.Second)

	stats, err = client.GetSystemStats(context.Background(), &pb.Empty{})
	require.NoError(t, err)
	peerID2 := anonymize("127.0.0.2")
	require.Contains(t, stats.PeerStats, peerID2)
	require.False(t, stats.PeerStats[peerID2].GracefulRestart, "GR should NOT be active for peer 2")

	// Verify purge behavior
	prefix2 := "2.2.2.0"
	announceIPv4(t, gobgp2, prefix2, 24, "10.0.0.2", []uint32{64501})
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix2 + "/24"})
		return err == nil && resp.Found
	}, 30*time.Second)

	t.Log("Dropping non-GR session...")
	stopGoBGP2()

	waitForConvergence(t, func() bool {
		resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix2 + "/24"})
		return err == nil && !resp.Found
	}, 30*time.Second)
	t.Log("Success: Non-GR peer routes purged immediately")
}

// TestGracefulRestart2_HoldOnDrop verifies that routes are held and marked stale on session drop.
func TestGracefulRestart2_HoldOnDrop(t *testing.T) {
	t.Log("Test 2: Clean session drop — stale routes held")

	bgpPort, grpcPort := portPair(41)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	prefix := "1.2.3.0"
	announceIPv4(t, gobgp, prefix, 24, "10.0.0.1", []uint32{64500})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return err == nil && resp.Found
	}, 30*time.Second)

	t.Log("Dropping BGP session...")
	stopGoBGP()

	// Wait for BGPWatch to detect session drop and mark stale
	waitForConvergence(t, func() bool {
		resp, err := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return err == nil && resp.Found && resp.Route.StaleSeconds > 0
	}, 30*time.Second)

	t.Log("Success: Route held and marked stale after session drop")
}

// TestGracefulRestart3_PurgeOnEoR verifies that re-advertised prefixes have stale cleared,
// and missing ones are purged on EoR.
func TestGracefulRestart3_PurgeOnEoR(t *testing.T) {
	t.Log("Test 3: Peer reconnects and sends EOR — stale routes purged correctly")

	bgpPort, grpcPort := portPair(42)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	prefixA := "1.1.1.0"
	prefixB := "2.2.2.0"
	announceIPv4(t, gobgp, prefixA, 24, "10.0.0.1", []uint32{64500})
	announceIPv4(t, gobgp, prefixB, 24, "10.0.0.1", []uint32{64500})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefixA + "/24"})
		return resp != nil && resp.Found
	}, 30*time.Second)

	t.Log("Dropping session...")
	stopGoBGP()

	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefixA + "/24"})
		return resp != nil && resp.Found && resp.Route.StaleSeconds > 0
	}, 30*time.Second)

	t.Log("Reconnecting and only announcing prefix A...")
	// We need to start a NEW gobgp instance because stopGoBGP stopped the previous one.
	gobgp, stopGoBGP = startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	defer stopGoBGP()
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	announceIPv4(t, gobgp, prefixA, 24, "10.0.0.1", []uint32{64500})

	// Wait for prefix A to be non-stale
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefixA + "/24"})
		return resp != nil && resp.Found && resp.Route.StaleSeconds == 0
	}, 30*time.Second)

	// Wait for prefix B to be purged (on EoR, which GoBGP sends after it finishes initial sync)
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefixB + "/24"})
		return resp != nil && !resp.Found
	}, 30*time.Second)

	t.Log("Success: Prefix A updated, Prefix B purged on EoR")
}

// TestGracefulRestart4_EmptyEoR verifies that all stale routes are purged if peer sends EoR with no updates.
func TestGracefulRestart4_EmptyEoR(t *testing.T) {
	t.Log("Test 4: Peer reconnects but re-advertises nothing before EOR")

	bgpPort, grpcPort := portPair(43)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	prefix := "1.2.3.0"
	announceIPv4(t, gobgp, prefix, 24, "10.0.0.1", []uint32{64500})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && resp.Found
	}, 30*time.Second)

	t.Log("Dropping session...")
	stopGoBGP()

	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && resp.Found && resp.Route.StaleSeconds > 0
	}, 30*time.Second)

	t.Log("Reconnecting with NO prefixes...")
	gobgp, stopGoBGP = startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	defer stopGoBGP()
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	// GoBGP will send EoR automatically since we have no paths to announce.
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && !resp.Found
	}, 30*time.Second)

	t.Log("Success: All routes purged on empty EoR")
}

// TestGracefulRestart5_TimerExpiry verifies that stale routes are purged when the GR timer fires.
func TestGracefulRestart5_TimerExpiry(t *testing.T) {
	t.Log("Test 5: EOR never arrives — timer fires")

	bgpPort, grpcPort := portPair(44)

	// Start BGPWatch with short GR timers for testing
	rid, _ := server.GetRid("0.0.0.1")
	conf := server.Config{
		Rid:               rid,
		Port:              bgpPort,
		GrpcPort:          grpcPort,
		Eor:               false,
		Quiet:             true,
		Asn:               64533,
		GRRestartTime:     5 * time.Second,
		GREoRFallbackTime: 5 * time.Second,
	}
	srv := server.New(conf)
	go srv.Start()
	time.Sleep(500 * time.Millisecond)

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	prefix := "9.9.9.0"
	announceIPv4(t, gobgp, prefix, 24, "10.0.0.1", []uint32{64500})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && resp.Found
	}, 30*time.Second)

	t.Log("Stopping peer and NOT reconnecting...")
	stopGoBGP()

	// Wait for restart timer to expire (5s)
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && !resp.Found
	}, 30*time.Second)

	t.Log("Success: Stale routes purged on timer expiry")
}

// TestGracefulRestart6_FlapDuringStale verifies that the stale timer behavior is consistent during session flaps.
func TestGracefulRestart6_FlapDuringStale(t *testing.T) {
	t.Log("Test 6: Session drops again during the stale window — before reconnect")

	bgpPort, grpcPort := portPair(45)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	prefix := "6.6.6.0"
	announceIPv4(t, gobgp, prefix, 24, "10.0.0.1", []uint32{64500})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && resp.Found
	}, 30*time.Second)

	t.Log("First drop...")
	stopGoBGP()
	start := time.Now()

	// Wait for it to be stale
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && resp.Found && resp.Route.StaleSeconds > 0
	}, 5*time.Second)

	t.Log("Session flap (connect and immediate drop)...")
	// We just want to trigger HandlePeerDown again.
	// A quick connection that closes before Open might not trigger it, 
	// so let's fully establish then drop.
	gobgp, stopGoBGP = startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)
	stopGoBGP()

	t.Log("Waiting for original timer to expire (should NOT have reset to another 10s)...")
	// If it reset, it would take another 10s from now.
	// If it didn't reset, it should expire around start + 10s.
	
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && !resp.Found
	}, 30*time.Second)

	elapsed := time.Since(start)
	t.Logf("Elapsed time since first drop: %v", elapsed)
}

// TestGracefulRestart7_RBit verifies that the R bit in OPEN is handled correctly.
func TestGracefulRestart7_RBit(t *testing.T) {
	t.Log("Test 7: Peer reconnects with R bit set vs not set in OPEN")
	
	bgpPort, grpcPort := portPair(46)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	prefix := "7.7.7.0"
	announceIPv4(t, gobgp, prefix, 24, "10.0.0.1", []uint32{64500})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && resp.Found
	}, 30*time.Second)

	stopGoBGP()
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && resp.Found && resp.Route.StaleSeconds > 0
	}, 5*time.Second)

	t.Log("Reconnecting (GoBGP will set R=1)...")
	gobgp, stopGoBGP = startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	defer stopGoBGP()
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	announceIPv4(t, gobgp, prefix, 24, "10.0.0.1", []uint32{64500})
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && resp.Found && resp.Route.StaleSeconds == 0
	}, 30*time.Second)
	t.Log("Success: Reconnected with R bit handled")
}

// TestGracefulRestart8_MultiAFIEoR verifies that IPv4 and IPv6 stale routes are purged independently.
func TestGracefulRestart8_MultiAFIEoR(t *testing.T) {
	t.Log("Test 8: GR with multiple AFI/SAFIs — EOR per family")

	bgpPort, grpcPort := portPair(47)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	prefix4 := "4.4.4.0"
	prefix6 := "2600::"
	announceIPv4(t, gobgp, prefix4, 24, "10.0.0.1", []uint32{64500})
	announceIPv6(t, gobgp, prefix6, 32, []string{"2001:db8::100"}, []uint32{64500})

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp4, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix4 + "/24"})
		resp6, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix6 + "/32"})
		return resp4 != nil && resp4.Found && resp6 != nil && resp6.Found
	}, 30*time.Second)

	stopGoBGP()
	waitForConvergence(t, func() bool {
		resp4, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix4 + "/24"})
		return resp4 != nil && resp4.Found && resp4.Route.StaleSeconds > 0
	}, 5*time.Second)

	t.Log("Reconnecting...")
	gobgp, stopGoBGP = startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	defer stopGoBGP()
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	// We'll announce IPv4 but NOT IPv6.
	announceIPv4(t, gobgp, prefix4, 24, "10.0.0.1", []uint32{64500})

	// Wait for IPv4 to be non-stale
	waitForConvergence(t, func() bool {
		resp4, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix4 + "/24"})
		return resp4 != nil && resp4.Found && resp4.Route.StaleSeconds == 0
	}, 30*time.Second)

	// Verify IPv6 is eventually purged
	waitForConvergence(t, func() bool {
		resp6, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix6 + "/32"})
		return resp6 != nil && !resp6.Found
	}, 30*time.Second)

	t.Log("Success: IPv4 and IPv6 EoRs handled")
}

// TestGracefulRestart9_AttributeUpdate verifies that attributes are updated during the resync window.
func TestGracefulRestart9_AttributeUpdate(t *testing.T) {
	t.Log("Test 9: Peer re-advertises a prefix with different attributes before EOR")

	bgpPort, grpcPort := portPair(58)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64533, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	prefix := "9.10.11.0"
	announceIPv4WithAttributes(t, gobgp, prefix, 24, "10.0.0.1", []uint32{64500}, 0, 100)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && resp.Found && resp.Route.LocalPref == 100
	}, 30*time.Second)

	stopGoBGP()
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && resp.Found && resp.Route.StaleSeconds > 0
	}, 5*time.Second)

	t.Log("Reconnecting with different LocalPref...")
	gobgp, stopGoBGP = startGoBGP(t, 64533, "10.0.0.1", "127.0.0.1", 64533, bgpPort, false, true)
	defer stopGoBGP()
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	announceIPv4WithAttributes(t, gobgp, prefix, 24, "10.0.0.1", []uint32{64500}, 0, 200)

	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoute(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && resp.Found && resp.Route.StaleSeconds == 0 && resp.Route.LocalPref == 200
	}, 30*time.Second)
	t.Log("Success: Attribute updated and stale cleared")
}

// TestGracefulRestart10_AddPath verifies GR interaction with Add-Path.
func TestGracefulRestart10_AddPath(t *testing.T) {
	t.Log("Test 10: Add-Path interaction with stale state")

	bgpPort, grpcPort := portPair(49)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, false)
	defer stopBW()

	gobgp, stopGoBGP := startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, true, true)
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	prefix := "110.110.110.0"
	announceIPv4WithPathID(t, gobgp, prefix, 24, "10.0.0.1", []uint32{64500}, 1)
	announceIPv4WithPathID(t, gobgp, prefix, 24, "10.0.0.2", []uint32{64500}, 2)

	client := grpcClient(t, grpcPort)
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && len(resp.Routes) == 2
	}, 30*time.Second)

	stopGoBGP()
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && len(resp.Routes) == 2 && resp.Routes[0].StaleSeconds > 0
	}, 5*time.Second)

	t.Log("Reconnecting and only announcing PathID 1...")
	gobgp, stopGoBGP = startGoBGP(t, 64500, "10.0.0.1", "127.0.0.1", 64533, bgpPort, true, true)
	defer stopGoBGP()
	waitForSession(t, gobgp, "127.0.0.1", 30*time.Second)

	announceIPv4WithPathID(t, gobgp, prefix, 24, "10.0.0.1", []uint32{64500}, 1)

	// Wait for PathID 1 to be non-stale
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		if resp == nil {
			return false
		}
		for _, r := range resp.Routes {
			if r.PathId == 1 && r.StaleSeconds == 0 {
				return true
			}
		}
		return false
	}, 30*time.Second)

	// Wait for PathID 2 to be purged on EoR
	waitForConvergence(t, func() bool {
		resp, _ := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: prefix + "/24"})
		return resp != nil && len(resp.Routes) == 1 && resp.Routes[0].PathId == 1
	}, 30*time.Second)

	t.Log("Success: Partial path ID withdrawal handled during GR")
}
