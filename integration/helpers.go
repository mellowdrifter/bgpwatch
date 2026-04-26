//go:build integration
// +build integration

package integration

import (
	"context"
	"fmt"
	"time"
	"testing"

	"github.com/mellowdrifter/bgpwatch/internal/server"
	pb "github.com/mellowdrifter/bgpwatch/proto"
	api "github.com/osrg/gobgp/v3/api"
	gobgpserver "github.com/osrg/gobgp/v3/pkg/server"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/types/known/anypb"
	"github.com/stretchr/testify/require"
)

func startBGPWatch(t *testing.T, bgpPort, grpcPort int, eor bool) func() {
	rid, err := server.GetRid("0.0.0.1")
	require.NoError(t, err)

	conf := server.Config{
		Rid:      rid,
		Port:     bgpPort,
		GrpcPort: grpcPort,
		Eor:      eor,
		Quiet:    true,
		Asn:      64533,
	}
	srv := server.New(conf)
	go srv.Start()
	
	// Wait a bit for servers to start
	time.Sleep(500 * time.Millisecond)
	
	return func() {
		// No graceful shutdown in bgpwatch yet, but we can close the listener if it were exposed.
		// For now, we rely on the test process exiting.
	}
}

func startGoBGP(t *testing.T, localAS uint32, routerID, peerAddr string,
	peerAS uint32, bgpPort int, addPath bool) (*gobgpserver.BgpServer, func()) {

	s := gobgpserver.NewBgpServer()
	go s.Serve()

	err := s.StartBgp(context.Background(), &api.StartBgpRequest{
		Global: &api.Global{
			Asn:        localAS,
			RouterId:   routerID,
			ListenPort: -1, // Don't listen; we connect outbound to bgpwatch
		},
	})
	require.NoError(t, err)

	peer := &api.Peer{
		Conf: &api.PeerConf{
			NeighborAddress: peerAddr,
			PeerAsn:          peerAS,
		},
		Transport: &api.Transport{
			RemotePort: uint32(bgpPort),
		},
	}

	// Enable Graceful Restart to ensure EoR is sent
	peer.GracefulRestart = &api.GracefulRestart{
		Enabled: true,
	}

	// Enable Add-Path if requested
	peer.AfiSafis = []*api.AfiSafi{
		{
			Config: &api.AfiSafiConfig{
				Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
			},
		},
		{
			Config: &api.AfiSafiConfig{
				Family: &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST},
			},
		},
	}

	if addPath {
		for _, fs := range peer.AfiSafis {
			fs.AddPaths = &api.AddPaths{
				Config: &api.AddPathsConfig{
					SendMax: 8,
					Receive: true,
				},
			}
		}
	}

	err = s.AddPeer(context.Background(), &api.AddPeerRequest{Peer: peer})
	require.NoError(t, err)

	cleanup := func() {
		s.Stop()
	}
	return s, cleanup
}

func waitForSession(t *testing.T, s *gobgpserver.BgpServer, peerAddr string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var established bool
		err := s.ListPeer(context.Background(), &api.ListPeerRequest{
			Address: peerAddr,
		}, func(p *api.Peer) {
			if p.State.SessionState == api.PeerState_ESTABLISHED {
				established = true
			}
		})
		if err == nil && established {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("BGP session with %s did not reach ESTABLISHED within %v", peerAddr, timeout)
}

func grpcClient(t *testing.T, grpcPort int) pb.BGPWatchClient {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	
	conn, err := grpc.DialContext(
		ctx,
		fmt.Sprintf("127.0.0.1:%d", grpcPort),
		grpc.WithInsecure(),
		grpc.WithBlock(),
	)
	require.NoError(t, err)
	t.Cleanup(func() { conn.Close() })
	return pb.NewBGPWatchClient(conn)
}

func announceIPv4(t *testing.T, s *gobgpserver.BgpServer,
	prefix string, maskLen uint32, nextHop string, asPath []uint32) {
	announceIPv4WithPathID(t, s, prefix, maskLen, nextHop, asPath, 0)
}

func announceIPv4WithPathID(t *testing.T, s *gobgpserver.BgpServer,
	prefix string, maskLen uint32, nextHop string, asPath []uint32, pathID uint32) {

	nlri, _ := anypb.New(&api.IPAddressPrefix{
		Prefix:    prefix,
		PrefixLen: maskLen,
	})
	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
	nh, _ := anypb.New(&api.NextHopAttribute{NextHop: nextHop})

	segments := []*api.AsSegment{
		{Type: api.AsSegment_AS_SEQUENCE, Numbers: asPath},
	}
	asp, _ := anypb.New(&api.AsPathAttribute{Segments: segments})

	_, err := s.AddPath(context.Background(), &api.AddPathRequest{
		Path: &api.Path{
			Family:         &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
			Nlri:           nlri,
			Pattrs:         []*anypb.Any{origin, nh, asp},
			Identifier:     pathID,
		},
	})
	require.NoError(t, err)
}

func withdrawIPv4(t *testing.T, s *gobgpserver.BgpServer,
	prefix string, maskLen uint32) {

	nlri, _ := anypb.New(&api.IPAddressPrefix{
		Prefix:    prefix,
		PrefixLen: maskLen,
	})
	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
	nh, _ := anypb.New(&api.NextHopAttribute{NextHop: "0.0.0.0"})

	err := s.DeletePath(context.Background(), &api.DeletePathRequest{
		Path: &api.Path{
			Family: &api.Family{Afi: api.Family_AFI_IP, Safi: api.Family_SAFI_UNICAST},
			Nlri:   nlri,
			Pattrs: []*anypb.Any{origin, nh},
		},
	})
	require.NoError(t, err)
}

func announceIPv6(t *testing.T, s *gobgpserver.BgpServer,
	prefix string, maskLen uint32, nextHop string, asPath []uint32) {

	family := &api.Family{Afi: api.Family_AFI_IP6, Safi: api.Family_SAFI_UNICAST}
	nlri, _ := anypb.New(&api.IPAddressPrefix{
		Prefix:    prefix,
		PrefixLen: maskLen,
	})
	origin, _ := anypb.New(&api.OriginAttribute{Origin: 0})
	
	mpreach, _ := anypb.New(&api.MpReachNLRIAttribute{
		Family:   family,
		NextHops: []string{nextHop},
		Nlris:    []*anypb.Any{nlri},
	})

	segments := []*api.AsSegment{
		{Type: api.AsSegment_AS_SEQUENCE, Numbers: asPath},
	}
	asp, _ := anypb.New(&api.AsPathAttribute{Segments: segments})

	_, err := s.AddPath(context.Background(), &api.AddPathRequest{
		Path: &api.Path{
			Family: family,
			Nlri:   nlri,
			Pattrs: []*anypb.Any{origin, mpreach, asp},
		},
	})
	require.NoError(t, err)
}

func waitForConvergence(t *testing.T, check func() bool, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("convergence check did not pass within timeout")
}
