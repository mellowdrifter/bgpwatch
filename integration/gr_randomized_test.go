//go:build integration
// +build integration

package integration

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"testing"
	"time"

	"github.com/mellowdrifter/bgpwatch/internal/server"
	pb "github.com/mellowdrifter/bgpwatch/proto"
	gobgpserver "github.com/osrg/gobgp/v3/pkg/server"
	"github.com/stretchr/testify/require"
)

type expectedRoute struct {
	prefix   netip.Prefix
	stale    bool
	pathID   uint32
	nextHop  string
}

type grModel struct {
	routes map[string]expectedRoute
	status server.PeerStatus
}

func TestGracefulRestart_Randomized(t *testing.T) {
	rand.Seed(time.Now().UnixNano())

	bgpPort, grpcPort := portPair(100)
	stopBW := startBGPWatch(t, bgpPort, grpcPort, true)
	defer stopBW()

	client := grpcClient(t, grpcPort)

	peerIP := "127.0.0.1"
	peerAsn := uint32(64500)
	routerID := "10.0.0.1"

	var gobgp *gobgpserver.BgpServer
	var stopGoBGP func()
	
	model := &grModel{
		routes: make(map[string]expectedRoute),
		status: server.StatusPurging, // Start as purging/none
	}

	numActions := 50
	if testing.Short() {
		numActions = 10
	}

	for i := 0; i < numActions; i++ {
		action := rand.Intn(7)
		t.Logf("Step %d: Action %d", i, action)

		switch action {
		case 0, 6: // Connect/Reconnect
			if gobgp == nil {
				t.Log("Action: Connect Peer")
				gobgp, stopGoBGP = startGoBGP(t, peerAsn, routerID, peerIP, 64533, bgpPort, true, true)
				waitForSession(t, gobgp, peerIP, 10*time.Second)
				model.status = server.StatusWaitingForEOR
				// Mark existing routes as stale when reconnecting
				for k, v := range model.routes {
					v.stale = true
					model.routes[k] = v
				}
			}
		case 1: // Disconnect
			if gobgp != nil {
				t.Log("Action: Disconnect Peer")
				stopGoBGP()
				gobgp = nil
				model.status = server.StatusGRStale
				// Mark all routes as stale
				for k, v := range model.routes {
					v.stale = true
					model.routes[k] = v
				}
			}
		case 2: // Announce random routes
			if gobgp != nil {
				t.Log("Action: Announce Routes")
				for j := 0; j < 5; j++ {
					pfxStr := fmt.Sprintf("192.168.%d.0", rand.Intn(255))
					prefix, _ := netip.ParsePrefix(pfxStr + "/24")
					pathID := uint32(rand.Intn(2))
					key := fmt.Sprintf("%s-%d", prefix.String(), pathID)
					
					announceIPv4WithPathID(t, gobgp, pfxStr, 24, "10.0.0.1", []uint32{peerAsn}, pathID)
					model.routes[key] = expectedRoute{
						prefix:  prefix,
						stale:   false,
						pathID:  pathID,
						nextHop: "10.0.0.1",
					}
				}
			}
		case 3: // Withdraw random routes
			if gobgp != nil && len(model.routes) > 0 {
				t.Log("Action: Withdraw Routes")
				// Get a random key from model
				var targetKey string
				for k := range model.routes {
					targetKey = k
					break
				}
				route := model.routes[targetKey]
				withdrawIPv4WithPathID(t, gobgp, route.prefix.Addr().String(), uint32(route.prefix.Bits()), route.pathID)
				delete(model.routes, targetKey)
			}
		case 4: // Wait a bit
			t.Log("Action: Wait")
			time.Sleep(2 * time.Second)
		case 5: // Verify state
			t.Log("Action: Verify State")
			verifyModel(t, client, model)
		}
	}
}

func verifyModel(t *testing.T, client pb.BGPWatchClient, model *grModel) {
	t.Helper()
	
	// Use a small timeout for convergence
	deadline := time.Now().Add(5 * time.Second)
	var peerStats *pb.PeerStats
	var stats *pb.SystemStatsResponse
	var err error

	peerID := anonymize("127.0.0.1")

	for time.Now().Before(deadline) {
		stats, err = client.GetSystemStats(context.Background(), &pb.Empty{})
		if err == nil {
			if ps, ok := stats.PeerStats[peerID]; ok {
				peerStats = ps
				// If we expected WaitingForEoR but it already reached Established, that's okay (converged fast)
				if model.status == server.StatusWaitingForEOR && peerStats.State == "Established" {
					model.status = server.StatusEstablished
					// When transitioned to Established, any remaining stale routes in model should be removed
					for k, v := range model.routes {
						if v.stale {
							delete(model.routes, k)
						}
					}
				}
				break
			}
		}
		time.Sleep(500 * time.Millisecond)
	}

	if model.status == server.StatusPurging && peerStats == nil {
		return
	}
	
	require.NotNil(t, peerStats, "Peer %s should be tracked in stats", peerID)
	t.Logf("Verifying state. Model: %v, BGPWatch: %s", model.status, peerStats.State)
	
	// Verify routes
	for _, expected := range model.routes {
		success := false
		var lastRoutes []*pb.Route
		
		start := time.Now()
		for time.Since(start) < 10*time.Second {
			resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: expected.prefix.String()})
			if err == nil {
				lastRoutes = resp.Routes
				for _, r := range resp.Routes {
					if r.PathId == expected.pathID {
						if expected.stale {
							if r.StaleSeconds > 0 {
								success = true
								break
							}
						} else {
							if r.StaleSeconds == 0 {
								success = true
								break
							}
						}
					}
				}
			}
			if success {
				break
			}
			time.Sleep(500 * time.Millisecond)
		}
		
		if !success {
			t.Errorf("Route verification failed for %s (PathID %d). Expected stale: %v. Last routes found: %+v", 
				expected.prefix, expected.pathID, expected.stale, lastRoutes)
		}
	}
}
