package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"regexp"
	"runtime"
	"strings"
	"time"
	"encoding/json"
	"net/http"

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
	peers := g.snapshotPeers()

	var totalV4Paths, totalV6Paths int64
	for _, p := range peers {
		totalV4Paths += int64(p.rib.V4PathCount())
		totalV6Paths += int64(p.rib.V6PathCount())
	}

	g.bgp.globalMasksMu.RLock()
	ipv4Count := int32(len(g.bgp.v4PrefixRefs))
	ipv6Count := int32(len(g.bgp.v6PrefixRefs))
	g.bgp.globalMasksMu.RUnlock()

	return &pb.TotalsResponse{
		Ipv4Count:      ipv4Count,
		Ipv6Count:      ipv6Count,
		TotalIpv4Paths: totalV4Paths,
		TotalIpv6Paths: totalV6Paths,
	}, nil
}

func (g *grpcServer) GetMasks(ctx context.Context, in *pb.Empty) (*pb.MasksResponse, error) {
	v4masks := make(map[int32]int32)
	v6masks := make(map[int32]int32)

	g.bgp.globalMasksMu.RLock()
	for k, v := range g.bgp.v4Masks {
		v4masks[k] = v
	}
	for k, v := range g.bgp.v6Masks {
		v6masks[k] = v
	}
	g.bgp.globalMasksMu.RUnlock()

	return &pb.MasksResponse{
		Ipv4Masks: v4masks,
		Ipv6Masks: v6masks,
	}, nil
}

func (g *grpcServer) snapshotPeers() []*peer {
	g.bgp.mutex.RLock()
	defer g.bgp.mutex.RUnlock()
	out := make([]*peer, len(g.bgp.peers))
	copy(out, g.bgp.peers)
	return out
}

func (g *grpcServer) GetSystemStats(ctx context.Context, in *pb.Empty) (*pb.SystemStatsResponse, error) {
	return g.bgp.collectStats(), nil
}

func (s *bgpWatchServer) collectStats() *pb.SystemStatsResponse {
	s.mutex.RLock()
	defer s.mutex.RUnlock()

	var m runtime.MemStats
	runtime.ReadMemStats(&m)

	var totalPeerRam uint64
	peerStats := make(map[string]*pb.PeerStats)
	for _, p := range s.peers {
		p.mutex.RLock()
		pmem := p.rib.MemoryUsage()
		peerRam := pmem.RoutingTablesEffective + pmem.RoutingTablesOverhead +
			pmem.RouteAttributesEffective + pmem.RouteAttributesOverhead
		totalPeerRam += peerRam

		var duration uint64
		if !p.establishedTime.IsZero() {
			duration = uint64(time.Since(p.establishedTime).Seconds())
		}

		peerStats[p.ip] = &pb.PeerStats{
			EstablishedDurationSeconds: duration,
			TotalAdvertisements:        p.updates,
			TotalWithdrawals:           p.withdraws,
			RibRamBytes:                peerRam,
			AddPath:                    len(p.param.AddPath) > 0,
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
		TotalPeerRibRamBytes: totalPeerRam,
		PeerStats:         peerStats,
	}
}

// GetRoute looks up a route by IP address (LPM) or CIDR prefix (exact match).
// The address field is parsed server-side: if it contains a "/" it is treated
// as an exact prefix match, otherwise as a longest prefix match.
// Bogon addresses are rejected before lookup.
func (g *grpcServer) GetRoute(ctx context.Context, in *pb.RouteRequest) (*pb.RouteLookupResponse, error) {
	addr := strings.TrimSpace(in.GetAddress())
	if addr == "" {
		return nil, status.Error(codes.InvalidArgument, "address is required")
	}

	peers := g.snapshotPeers()
	var candidates []routing_table.Route
	var peerIPs []string

	for _, p := range peers {
		r, err := g.performLookup(p.rib, addr)
		if err != nil {
			continue
		}
		if r != nil {
			candidates = append(candidates, *r)
			peerIPs = append(peerIPs, p.ip)
		}
	}

	if len(candidates) == 0 {
		return &pb.RouteLookupResponse{Found: false}, nil
	}

	// Pick best candidate
	bestIdx := 0
	for i := 1; i < len(candidates); i++ {
		curr := candidates[i]
		best := candidates[bestIdx]

		better := false
		if curr.Attributes.LocalPref > best.Attributes.LocalPref {
			better = true
		} else if curr.Attributes.LocalPref == best.Attributes.LocalPref {
			if len(curr.Attributes.AsPath) < len(best.Attributes.AsPath) {
				better = true
			} else if len(curr.Attributes.AsPath) == len(best.Attributes.AsPath) {
				if curr.PathID < best.PathID {
					better = true
				}
			}
		}
		if better {
			bestIdx = i
		}
	}

	return &pb.RouteLookupResponse{
		Found: true,
		Route: formatRouteResponse(&candidates[bestIdx], peerIPs[bestIdx]),
	}, nil
}

func formatRouteResponse(r *routing_table.Route, peerIP string) *pb.Route {
	if r == nil {
		return nil
	}
	return &pb.Route{
		Prefix:           r.Prefix.String(),
		PeerIp:           peerIP,
		AsPath:           r.Attributes.AsPath,
		LocalPref:        r.Attributes.LocalPref,
		Communities:      formatRouteCommunities(r.Attributes.Communities),
		LargeCommunities: formatRouteLargeCommunities(r.Attributes.LargeCommunities),
		PathId:           r.PathID,
	}
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

	var results []*pb.Route
	for _, p := range peers {
		routes, err := g.performMultiLookup(p.rib, addr)
		if err != nil {
			continue
		}

		for _, r := range routes {
			results = append(results, formatRouteResponse(&r, p.ip))
		}
	}

	return &pb.RoutesResponse{Routes: results}, nil
}

func (g *grpcServer) performLookup(rib routing_table.Rib, addr string) (*routing_table.Route, error) {
	if strings.Contains(addr, "/") {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid prefix %q: %v", addr, err)
		}
		prefix = prefix.Masked()

		ip := prefix.Addr()
		if !bogons.IsPublicIP(ip.AsSlice()) {
			return nil, status.Errorf(codes.InvalidArgument, "%s is a bogon prefix", addr)
		}

		if ip.Is4() {
			return rib.LookupIPv4(prefix), nil
		}
		return rib.LookupIPv6(prefix), nil
	}

	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid address %q: %v", addr, err)
	}

	if !bogons.IsPublicIP(ip.AsSlice()) {
		return nil, status.Errorf(codes.InvalidArgument, "%s is a bogon address", addr)
	}

	if ip.Is4() {
		return rib.SearchIPv4(ip), nil
	}
	return rib.SearchIPv6(ip), nil
}

func (g *grpcServer) performMultiLookup(rib routing_table.Rib, addr string) ([]routing_table.Route, error) {
	if strings.Contains(addr, "/") {
		prefix, err := netip.ParsePrefix(addr)
		if err != nil {
			return nil, status.Errorf(codes.InvalidArgument, "invalid prefix %q: %v", addr, err)
		}
		prefix = prefix.Masked()

		ip := prefix.Addr()
		if !bogons.IsPublicIP(ip.AsSlice()) {
			return nil, status.Errorf(codes.InvalidArgument, "%s is a bogon prefix", addr)
		}

		if ip.Is4() {
			return rib.AllPathsIPv4(prefix), nil
		}
		return rib.AllPathsIPv6(prefix), nil
	}

	ip, err := netip.ParseAddr(addr)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid address %q: %v", addr, err)
	}

	if !bogons.IsPublicIP(ip.AsSlice()) {
		return nil, status.Errorf(codes.InvalidArgument, "%s is a bogon address", addr)
	}

	if ip.Is4() {
		return rib.AllPathsSearchIPv4(ip), nil
	}
	return rib.AllPathsSearchIPv6(ip), nil
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

// GetPrefixesByOrigin returns all IPv4 and IPv6 prefixes originated by the given ASN (lightweight).
func (g *grpcServer) GetPrefixesByOrigin(ctx context.Context, in *pb.OriginRequest) (*pb.PrefixesResponse, error) {
	asn := in.GetAsn()
	if asn == 0 {
		return nil, status.Error(codes.InvalidArgument, "ASN is required")
	}

	if !bogons.ValidPublicASN(asn) {
		return nil, status.Errorf(codes.InvalidArgument, "AS%d is not a valid public ASN", asn)
	}

	peers := g.snapshotPeers()
	seen := make(map[netip.Prefix]struct{})
	var results []*pb.Prefix

	for _, p := range peers {
		p.mutex.RLock()
		v4, v6 := p.rib.PrefixesByOriginASN(asn)
		for _, r := range v4 {
			if _, ok := seen[r.Prefix]; !ok {
				seen[r.Prefix] = struct{}{}
				results = append(results, &pb.Prefix{Prefix: r.Prefix.String()})
			}
		}
		for _, r := range v6 {
			if _, ok := seen[r.Prefix]; !ok {
				seen[r.Prefix] = struct{}{}
				results = append(results, &pb.Prefix{Prefix: r.Prefix.String()})
			}
		}
		p.mutex.RUnlock()
	}

	return &pb.PrefixesResponse{
		Prefixes: results,
	}, nil
}

// GetRoutesByOrigin returns all IPv4 and IPv6 routes originated by the given ASN (detailed).
func (g *grpcServer) GetRoutesByOrigin(ctx context.Context, in *pb.OriginRequest) (*pb.RoutesResponse, error) {
	asn := in.GetAsn()
	if asn == 0 {
		return nil, status.Error(codes.InvalidArgument, "ASN is required")
	}

	if !bogons.ValidPublicASN(asn) {
		return nil, status.Errorf(codes.InvalidArgument, "AS%d is not a valid public ASN", asn)
	}

	peers := g.snapshotPeers()
	type candidate struct {
		route  routing_table.Route
		peerIP string
	}
	prefixToBest := make(map[netip.Prefix]candidate)

	for _, p := range peers {
		p.mutex.RLock()
		v4, v6 := p.rib.PrefixesByOriginASN(asn)
		all := append(v4, v6...)
		for _, r := range all {
			existing, ok := prefixToBest[r.Prefix]
			if !ok || g.isBetter(r, existing.route) {
				prefixToBest[r.Prefix] = candidate{route: r, peerIP: p.ip}
			}
		}
		p.mutex.RUnlock()
	}

	results := make([]*pb.Route, 0, len(prefixToBest))
	for _, c := range prefixToBest {
		results = append(results, formatRouteResponse(&c.route, c.peerIP))
	}

	return &pb.RoutesResponse{
		Routes: results,
	}, nil
}

// GetPrefixesByAsPath returns all IPv4 and IPv6 prefixes matching the given AS path regex.
func (g *grpcServer) GetPrefixesByAsPath(ctx context.Context, in *pb.AsPathRequest) (*pb.RoutesResponse, error) {
	regexStr := in.GetRegex()
	if regexStr == "" {
		return nil, status.Error(codes.InvalidArgument, "regex is required")
	}

	goRegex := ciscoRegexpToGo(regexStr)
	re, err := regexp.Compile(goRegex)
	if err != nil {
		return nil, status.Errorf(codes.InvalidArgument, "invalid regex %q: %v", regexStr, err)
	}

	peers := g.snapshotPeers()
	type candidate struct {
		route  routing_table.Route
		peerIP string
	}
	prefixToBest := make(map[netip.Prefix]candidate)

	for _, p := range peers {
		p.mutex.RLock()
		v4, v6 := p.rib.PrefixesByAsPathRegex(re)
		all := append(v4, v6...)
		for _, r := range all {
			existing, ok := prefixToBest[r.Prefix]
			if !ok || g.isBetter(r, existing.route) {
				prefixToBest[r.Prefix] = candidate{route: r, peerIP: p.ip}
			}
		}
		p.mutex.RUnlock()
	}

	results := make([]*pb.Route, 0, len(prefixToBest))
	for _, c := range prefixToBest {
		results = append(results, formatRouteResponse(&c.route, c.peerIP))
	}

	return &pb.RoutesResponse{
		Routes: results,
	}, nil
}

func (g *grpcServer) isBetter(curr, best routing_table.Route) bool {
	if curr.Attributes.LocalPref > best.Attributes.LocalPref {
		return true
	}
	if curr.Attributes.LocalPref < best.Attributes.LocalPref {
		return false
	}
	if len(curr.Attributes.AsPath) < len(best.Attributes.AsPath) {
		return true
	}
	if len(curr.Attributes.AsPath) > len(best.Attributes.AsPath) {
		return false
	}
	return curr.PathID < best.PathID
}

func ciscoRegexpToGo(cisco string) string {
	// Cisco _ matches delimiters (start, end, space, comma, etc.)
	// Our AS path is space-separated.
	return strings.ReplaceAll(cisco, "_", "(?:^| +|$)")
}

func (s *bgpWatchServer) startGRPC(port int) {
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", port))
	if err != nil {
		log.Fatalf("failed to listen for gRPC: %v", err)
	}

	srv := grpc.NewServer()
	pb.RegisterBGPWatchServer(srv, &grpcServer{bgp: s})
	reflection.Register(srv)

	// Add HTTP wrapper for system stats
	go func() {
		http.HandleFunc("/stats", func(w http.ResponseWriter, r *http.Request) {
			stats := s.collectStats()
			w.Header().Set("Content-Type", "application/json")
			w.Header().Set("Access-Control-Allow-Origin", "*")
			json.NewEncoder(w).Encode(stats)
		})
		log.Printf("HTTP stats server listening on port 1180\n")
		if err := http.ListenAndServe(":1180", nil); err != nil {
			log.Printf("HTTP server failed: %v\n", err)
		}
	}()

	log.Printf("gRPC server listening on port %d\n", port)
	if err := srv.Serve(lis); err != nil {
		log.Fatalf("gRPC server failed: %v", err)
	}
}
