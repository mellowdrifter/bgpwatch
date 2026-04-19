package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"strings"

	"github.com/mellowdrifter/bogons"
	"github.com/mellowdrifter/routing_table"
	pb "github.com/mellowdrifter/bgpwatch/proto"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/reflection"
	"google.golang.org/grpc/status"
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

// GetRoute looks up a route by IP address (LPM) or CIDR prefix (exact match).
// The address field is parsed server-side: if it contains a "/" it is treated
// as an exact prefix match, otherwise as a longest prefix match.
// Bogon addresses are rejected before lookup.
func (g *grpcServer) GetRoute(ctx context.Context, in *pb.RouteRequest) (*pb.RouteResponse, error) {
	addr := strings.TrimSpace(in.GetAddress())
	if addr == "" {
		return nil, status.Error(codes.InvalidArgument, "address is required")
	}

	var route *routing_table.Route

	if strings.Contains(addr, "/") {
		// Exact prefix match mode
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid prefix %q: %v", addr, err)
		}
		prefix = prefix.Masked()

		// Bogon check on the prefix address
		ip := prefix.Addr()
		if !bogons.IsPublicIP(ip.AsSlice()) {
			return nil, status.Errorf(codes.InvalidArgument, "%s is a bogon prefix", addr)
		}

		if ip.Is4() {
			route = g.bgp.rib.LookupIPv4(prefix)
		} else {
			route = g.bgp.rib.LookupIPv6(prefix)
		}
	} else {
		// Longest prefix match mode
		ip, err := netip.ParseAddr(addr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid address %q: %v", addr, err)
		}

		// Bogon check
		if !bogons.IsPublicIP(ip.AsSlice()) {
			return nil, status.Errorf(codes.InvalidArgument, "%s is a bogon address", addr)
		}

		if ip.Is4() {
			route = g.bgp.rib.SearchIPv4(ip)
		} else {
			route = g.bgp.rib.SearchIPv6(ip)
		}
	}

	// Not found — return a clean response with found=false
	if route == nil {
		return &pb.RouteResponse{Found: false}, nil
	}

	return &pb.RouteResponse{
		Found:            true,
		Prefix:           route.Prefix.String(),
		AsPath:           formatRouteASPath(route.Attributes.AsPath),
		LocalPref:        route.Attributes.LocalPref,
		Communities:      formatRouteCommunities(route.Attributes.Communities),
		LargeCommunities: formatRouteLargeCommunities(route.Attributes.LargeCommunities),
	}, nil
}

// formatRouteASPath renders an AS path slice as a space-separated string.
func formatRouteASPath(asPath []uint32) string {
	if len(asPath) == 0 {
		return ""
	}
	parts := make([]string, len(asPath))
	for i, asn := range asPath {
		parts[i] = fmt.Sprintf("%d", asn)
	}
	return strings.Join(parts, " ")
}

// formatRouteCommunities renders standard BGP communities as "high:low" strings.
func formatRouteCommunities(communities []uint32) []string {
	if len(communities) == 0 {
		return nil
	}
	result := make([]string, len(communities))
	for i, c := range communities {
		result[i] = fmt.Sprintf("%d:%d", c>>16, c&0xFFFF)
	}
	return result
}

// formatRouteLargeCommunities renders large communities as "admin:high:low" strings.
func formatRouteLargeCommunities(lc []routing_table.LargeCommunity) []string {
	if len(lc) == 0 {
		return nil
	}
	result := make([]string, len(lc))
	for i, c := range lc {
		result[i] = fmt.Sprintf("%d:%d:%d", c.GlobalAdmin, c.LocalData1, c.LocalData2)
	}
	return result
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
