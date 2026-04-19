package main

import (
	"context"
	"fmt"
	"log"
	"net"

	pb "github.com/mellowdrifter/bgpwatch/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/reflection"
)

type grpcServer struct {
	pb.UnimplementedBGPWatchServer
	bgp *bgpWatchServer
}

func (g *grpcServer) GetTotals(ctx context.Context, in *pb.Empty) (*pb.TotalsResponse, error) {
	g.bgp.mutex.RLock()
	defer g.bgp.mutex.RUnlock()

	v4 := g.bgp.rib.V4Count()
	v6 := g.bgp.rib.V6Count()

	return &pb.TotalsResponse{
		Ipv4Count: int32(v4),
		Ipv6Count: int32(v6),
	}, nil
}

func (g *grpcServer) GetMasks(ctx context.Context, in *pb.Empty) (*pb.MasksResponse, error) {
	g.bgp.mutex.RLock()
	defer g.bgp.mutex.RUnlock()

	v4masks := make(map[int32]int32)
	v6masks := make(map[int32]int32)

	pv4, pv6 := g.bgp.rib.GetSubnets()
	for k, v := range pv4 {
		v4masks[int32(k)] += int32(v)
	}
	for k, v := range pv6 {
		v6masks[int32(k)] += int32(v)
	}

	return &pb.MasksResponse{
		Ipv4Masks: v4masks,
		Ipv6Masks: v6masks,
	}, nil
}

func (g *grpcServer) GetSystemStats(ctx context.Context, in *pb.Empty) (*pb.SystemStatsResponse, error) {
	g.bgp.mutex.RLock()
	defer g.bgp.mutex.RUnlock()

	globalMem := g.bgp.rib.MemoryUsage()
	totalRam := globalMem.RoutingTablesEffective + globalMem.RoutingTablesOverhead +
		globalMem.RouteAttributesEffective + globalMem.RouteAttributesOverhead

	peerRam := make(map[string]uint64)
	for _, p := range g.bgp.peers {
		pmem := p.rib.MemoryUsage()
		peerRam[p.ip] = pmem.RoutingTablesEffective + pmem.RoutingTablesOverhead +
			pmem.RouteAttributesEffective + pmem.RouteAttributesOverhead
	}

	return &pb.SystemStatsResponse{
		TotalRamBytes: totalRam,
		PeerRamBytes:  peerRam,
	}, nil
}

func (s *bgpWatchServer) startGRPC(port int) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen for gRPC: %v", err)
	}

	srv := grpc.NewServer()
	pb.RegisterBGPWatchServer(srv, &grpcServer{bgp: s})
	reflection.Register(srv)

	log.Printf("gRPC server listening on port %d\n", port)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("gRPC server failed: %v", err)
	}
}
