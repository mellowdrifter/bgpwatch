package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"runtime"
	"strings"
	"time"

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

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	globalMem := g.bgp.rib.MemoryUsage()
	globalRam := globalMem.RoutingTablesEffective + globalMem.RoutingTablesOverhead +
		globalMem.RouteAttributesEffective + globalMem.RouteAttributesOverhead

	peerStats := make(map[string]*pb.PeerStats)
	for _, p := range g.bgp.peers {
		p.mutex.RLock()
		pmem := p.rib.MemoryUsage()
		peerRam := pmem.RoutingTablesEffective + pmem.RoutingTablesOverhead +
			pmem.RouteAttributesEffective + pmem.RouteAttributesOverhead

		var duration uint64
		if !p.establishedTime.IsZero() {
			duration = uint64(time.Since(p.establishedTime).Seconds())
		}

		peerStats[p.ip] = &pb.PeerStats{
			EstablishedDurationSeconds: duration,
			TotalAdvertisements:        p.updates,
			TotalWithdrawals:           p.withdraws,
			RibRamBytes:                peerRam,
		}
		p.mutex.RUnlock()
	}

	return &pb.SystemStatsResponse{
		TotalAppRamBytes:  m.Sys,
		HeapAllocBytes:    m.HeapAlloc,
		HeapSysBytes:      m.HeapSys,
		HeapIdleBytes:     m.HeapIdle,
		HeapReleasedBytes: m.HeapReleased,
		NumGc:             m.NumGC,
		GlobalRibRamBytes: globalRam,
		PeerStats:         peerStats,
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

	route, err := g.performLookup(g.bgp.rib, addr)
	if err != nil {
		return nil, err
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

// GetRoutes looks up a route across all peers.
func (g *grpcServer) GetRoutes(ctx context.Context, in *pb.RouteRequest) (*pb.RoutesResponse, error) {
	addr := strings.TrimSpace(in.GetAddress())
	if addr == "" {
		return nil, status.Error(codes.InvalidArgument, "address is required")
	}

	g.bgp.mutex.RLock()
	peers := make([]*peer, len(g.bgp.peers))
	copy(peers, g.bgp.peers)
	g.bgp.mutex.RUnlock()

	var results []*pb.RouteResponse
	for _, p := range peers {
		route, err := g.performLookup(p.rib, addr)
		if err != nil {
			// Skip peers that cause parsing errors or bogon hits (though should be consistent)
			continue
		}

		if route != nil {
			results = append(results, &pb.RouteResponse{
				Found:            true,
				Prefix:           route.Prefix.String(),
				AsPath:           formatRouteASPath(route.Attributes.AsPath),
				LocalPref:        route.Attributes.LocalPref,
				Communities:      formatRouteCommunities(route.Attributes.Communities),
				LargeCommunities: formatRouteLargeCommunities(route.Attributes.LargeCommunities),
				PeerIp:           p.ip,
			})
		}
	}

	return &pb.RoutesResponse{Routes: results}, nil
}

func (g *grpcServer) performLookup(rib routing_table.Rib, addr string) (*routing_table.Route, error) {
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
			return rib.LookupIPv4(prefix), nil
		}
		return rib.LookupIPv6(prefix), nil
	}

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
		return rib.SearchIPv4(ip), nil
	}
	return rib.SearchIPv6(ip), nil
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

// formatRouteCommunities renders standard BGP communities as structured messages.
func formatRouteCommunities(communities []uint32) []*pb.Community {
	if len(communities) == 0 {
		return nil
	}
	result := make([]*pb.Community, len(communities))
	for i, c := range communities {
		result[i] = &pb.Community{
			High: c >> 16,
			Low:  c & 0xFFFF,
		}
	}
	return result
}

// formatRouteLargeCommunities renders large communities as structured messages.
func formatRouteLargeCommunities(lc []routing_table.LargeCommunity) []*pb.LargeCommunity {
	if len(lc) == 0 {
		return nil
	}
	result := make([]*pb.LargeCommunity, len(lc))
	for i, c := range lc {
		result[i] = &pb.LargeCommunity{
			GlobalAdmin: c.GlobalAdmin,
			LocalData1:  c.LocalData1,
			LocalData2:  c.LocalData2,
		}
	}
	return result
}

// GetPrefixesByOrigin returns all IPv4 and IPv6 prefixes originated by the given ASN.
// The origin ASN is the last ASN in the AS path. Bogon ASNs are rejected.
func (g *grpcServer) GetPrefixesByOrigin(ctx context.Context, in *pb.OriginRequest) (*pb.OriginResponse, error) {
	asn := in.GetAsn()
	if asn == 0 {
		return nil, status.Error(codes.InvalidArgument, "ASN is required")
	}

	if !bogons.ValidPublicASN(asn) {
		return nil, status.Errorf(codes.InvalidArgument, "AS%d is not a valid public ASN", asn)
	}

	v4prefixes, v6prefixes := g.bgp.rib.PrefixesByOriginASN(asn)

	v4strs := make([]string, len(v4prefixes))
	for i, p := range v4prefixes {
		v4strs[i] = p.String()
	}

	v6strs := make([]string, len(v6prefixes))
	for i, p := range v6prefixes {
		v6strs[i] = p.String()
	}

	return &pb.OriginResponse{
		Ipv4Prefixes: v4strs,
		Ipv6Prefixes: v6strs,
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
