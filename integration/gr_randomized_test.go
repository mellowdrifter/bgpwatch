//go:build integration
// +build integration

package integration

import (
	"context"
	"fmt"
	"math/rand"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/mellowdrifter/bgpwatch/internal/server"
	pb "github.com/mellowdrifter/bgpwatch/proto"
	gobgpserver "github.com/osrg/gobgp/v3/pkg/server"
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

	peerID := anonymize("127.0.0.1")
	deadline := time.Now().Add(15 * time.Second)

	for time.Now().Before(deadline) {
		// 1. Verify Peer State
		stats, err := client.GetSystemStats(context.Background(), &pb.Empty{})
		if err != nil {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		peerStats, ok := stats.PeerStats[peerID]
		if !ok {
			time.Sleep(500 * time.Millisecond)
			continue
		}

		// If we expected WaitingForEoR but it already reached Established, that's okay
		if model.status == server.StatusWaitingForEOR && peerStats.State == "Established" {
			model.status = server.StatusEstablished
			for k, v := range model.routes {
				if v.stale {
					delete(model.routes, k)
				}
			}
		}

		// 2. Verify all routes
		var failingRoutes []string
		for _, expected := range model.routes {
			success := false
			resp, err := client.GetRoutes(context.Background(), &pb.RouteRequest{Address: expected.prefix.String()})
			if err == nil {
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
			if !success {
				var actual string
				if err != nil {
					actual = fmt.Sprintf("Error: %v", err)
				} else if resp == nil || len(resp.Routes) == 0 {
					actual = "Not Found"
				} else {
					actual = fmt.Sprintf("Routes: %+v", resp.Routes)
				}
				failingRoutes = append(failingRoutes, fmt.Sprintf("%s (PathID %d): expected stale=%v, actual=%s", 
					expected.prefix, expected.pathID, expected.stale, actual))
			}
		}

		if len(failingRoutes) == 0 {
			t.Logf("Verification success. State: %s, Routes: %d", peerStats.State, len(model.routes))
			return
		}

		if time.Now().After(deadline) {
			t.Errorf("Verification failed after 15s. State: %s. Failing routes:\n%s", 
				peerStats.State, strings.Join(failingRoutes, "\n"))
			return
		}

		time.Sleep(500 * time.Millisecond)
	}
}
