package server

import (
	"context"
	"fmt"
	"log"
	"net"
	"net/netip"
	"runtime/debug"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mellowdrifter/bgpwatch/internal/bgp"
	"github.com/mellowdrifter/bgpwatch/internal/procstats"
	"github.com/mellowdrifter/routing_table"
	"google.golang.org/grpc"
)

type Server struct {
	listener      net.Listener
	peers         []*peer
	mutex         sync.RWMutex
	globalMasksMu sync.RWMutex
	v4Masks       map[int32]int32
	v6Masks       map[int32]int32
	v4PrefixRefs  map[netip.Prefix]uint16
	v6PrefixRefs  map[netip.Prefix]uint16
	v4AttrTable   *routing_table.AttrTable
	v6AttrTable   *routing_table.AttrTable
	sampler       *procstats.Sampler
	Conf          Config
	grManager     GracefulRestartManager
	grpcServer    *grpc.Server
	peerStats     map[string]*persistentPeerStats
}

type persistentPeerStats struct {
	flaps            uint32
	lastNotification string
}

type Config struct {
	Rid               bgp.BGPID
	Port              int
	GrpcPort          int
	HttpPort          int
	Logfile           string
	Eor               bool
	Quiet             bool
	IgnoreCommunities bool
	PeersConfig       map[string]PeerConfig
	Asn               uint32
	GRRestartTime     time.Duration
	GREoRFallbackTime time.Duration
}

func New(conf Config) *Server {
	s := &Server{
		mutex:        sync.RWMutex{},
		v4Masks:      make(map[int32]int32),
		v6Masks:      make(map[int32]int32),
		v4PrefixRefs: make(map[netip.Prefix]uint16),
		v6PrefixRefs: make(map[netip.Prefix]uint16),
		v4AttrTable:  routing_table.NewAttrTable(),
		v6AttrTable:  routing_table.NewAttrTable(),
		sampler:      procstats.NewSampler(30 * time.Second),
		Conf:         conf,
		peerStats:    make(map[string]*persistentPeerStats),
	}
	s.grManager = NewGracefulRestartManager(s)
	return s
}

func (s *Server) Start() {
	s.listen(s.Conf)
	go s.clean()
	s.grpcServer = s.startGRPC(s.Conf.GrpcPort)

	for {
		conn, err := s.listener.Accept()
		if err != nil {
			if strings.Contains(err.Error(), "use of closed network connection") {
				return
			}
			log.Printf("%v\n", err)
		} else {
			peer := s.accept(conn)
			if peer != nil {
				go peer.peerWorker()
			}
		}
	}
}

func (s *Server) Stop() {
	s.mutex.Lock()
	defer s.mutex.Unlock()

	if s.listener != nil {
		s.listener.Close()
	}
	if s.grpcServer != nil {
		s.grpcServer.Stop()
	}

	for _, p := range s.peers {
		if p.conn != nil {
			p.conn.Close()
		}
	}
	s.peers = nil
}

// GetRid converts the string RID to actual BGPID.
func GetRid(srid string) (bgp.BGPID, error) {
	s := strings.Split(srid, ".")
	var rid bgp.BGPID
	if len(s) != 4 {
		return rid, fmt.Errorf("RID too short")
	}

	for i := 0; i < 4; i++ {
		num, err := strconv.ParseInt(s[i], 10, 16)
		if err != nil {
			return rid, err
		}
		rid[i] = byte(uint8(num))
	}

	return rid, nil
}

// clean checks for and removes stale clients that haven't sent a keepalive within their holdtime.
func (s *Server) clean() {
	ticker := time.NewTicker(30 * time.Second)
	for range ticker.C {
		s.mutex.RLock()
		now := time.Now()
		var dead []*peer
		for _, p := range s.peers {
			p.mutex.RLock()
			if p.holdtime > 0 && !p.lastKeepalive.IsZero() {
				if now.Sub(p.lastKeepalive) > time.Duration(p.holdtime)*time.Second {
					dead = append(dead, p)
				}
			}
			p.mutex.RUnlock()
		}
		s.mutex.RUnlock()

		for _, p := range dead {
			log.Printf("Holdtimer expired for %s", p.conn.RemoteAddr().String())
			p.conn.Write(bgp.CreateNotification(bgp.HoldTimeExpired, 0))
			s.mutex.Lock()
			if _, ok := s.peerStats[p.ip]; !ok {
				s.peerStats[p.ip] = &persistentPeerStats{}
			}
			s.peerStats[p.ip].lastNotification = "HOLD TIMER"
			s.mutex.Unlock()
			p.conn.Close()
		}
	}
}

// accept adds a new client to the current list of clients being served.
func (s *Server) accept(conn net.Conn) *peer {
	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// Whitelist check
	if s.Conf.PeersConfig != nil {
		if _, ok := s.Conf.PeersConfig[ip]; !ok {
			log.Printf("Connection from %v ignored (not in config)\n", conn.RemoteAddr().String())
			conn.Close()
			return nil
		}
	}

	log.Printf("Connection from %v, total peers: %d\n",
		conn.RemoteAddr().String(), len(s.peers)+1)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	var oldV4Rib *routing_table.IPv4Rib
	var oldV6Rib *routing_table.IPv6Rib
	var oldStatus uint32
	var oldStaleSince time.Time

	// If new client trying to connect with existing connection, remove old peer from pool
	for i, check := range s.peers {
		if ip == check.ip {
			check.mutex.Lock()
			oldV4Rib = check.v4rib
			oldV6Rib = check.v6rib
			oldStatus = check.status.Load()
			oldStaleSince = check.staleSince
			isGR := check.param.GracefulRestart
			check.v4rib = nil
			check.v6rib = nil
			check.mutex.Unlock()

			// If old peer had GR enabled and wasn't already stale,
			// mark the stolen RIBs as stale now (since old peer's remove()
			// won't do it — it will see the peer is no longer in the list).
			if isGR && PeerStatus(oldStatus) == StatusEstablished {
				if oldV4Rib != nil {
					oldV4Rib.MarkAllStale()
				}
				if oldV6Rib != nil {
					oldV6Rib.MarkAllStale()
				}
				oldStatus = uint32(StatusGRStale)
				oldStaleSince = time.Now()
			}

			check.conn.Close()
			s.peers = append(s.peers[:i], s.peers[i+1:]...)
			if _, ok := s.peerStats[ip]; !ok {
				s.peerStats[ip] = &persistentPeerStats{}
			}
			s.peerStats[ip].flaps++
			break
		}
	}

	peer := &peer{
		server:    s,
		conn:      conn,
		rid:       s.Conf.Rid,
		weor:      s.Conf.Eor,
		quiet:     s.Conf.Quiet,
		ip:        ip,
		mutex:     sync.RWMutex{},
		startTime: time.Now(),
		v4rib:     oldV4Rib,
		v6rib:     oldV6Rib,
	}
	if oldStatus == uint32(StatusEstablished) && s.Conf.Eor {
		peer.status.Store(uint32(StatusWaitingForEOR))
	} else {
		peer.status.Store(oldStatus)
	}
	peer.staleSince = oldStaleSince

	s.peers = append(s.peers, peer)
	peerIPs := make([]string, len(s.peers))
	for i, p := range s.peers {
		peerIPs[i] = p.ip
	}
	log.Printf("Peer list after add: %v\n", peerIPs)

	return peer
}

// remove removes a client from the current list of clients being served.
func (s *Server) remove(p *peer) {
	p.conn.Close()

	p.mutex.RLock()
	isGR := p.param.GracefulRestart
	p.mutex.RUnlock()

	if isGR {
		// Check if this peer is still in the peers list.
		// If it was already replaced by accept() during reconnection,
		// the new peer's HandleOpen will handle the GR transition.
		s.mutex.RLock()
		stillActive := false
		for _, check := range s.peers {
			if check == p {
				stillActive = true
				break
			}
		}
		s.mutex.RUnlock()

		if stillActive {
			log.Printf("Peer %s disconnected, holding routes (Graceful Restart)\n", p.ip)
			if p.v4rib != nil {
				p.v4rib.MarkAllStale()
			}
			if p.v6rib != nil {
				p.v6rib.MarkAllStale()
			}
			p.mutex.Lock()
			p.staleSince = time.Now()
			p.mutex.Unlock()
			_ = s.grManager.HandlePeerDown(context.Background(), p.ip)
			return
		}
		// Peer was replaced — the new peer has the RIBs, do nothing
		log.Printf("Old peer %s was already replaced, skipping GR handling\n", p.ip)
		return
	}

	log.Printf("Removing dead peer %s\n", p.conn.RemoteAddr().String())

	s.mutex.Lock()
	for i, check := range s.peers {
		if check == p {
			s.peers = append(s.peers[:i], s.peers[i+1:]...)
			break
		}
	}
	s.mutex.Unlock()

	// Clean up global refs and peer's memory
	p.mutex.Lock()
	var v4Prefixes []netip.Prefix
	var v6Prefixes []netip.Prefix
	if p.v4rib != nil {
		v4Prefixes = p.v4rib.AllPrefixes()
		p.v4rib = nil
	}
	if p.v6rib != nil {
		v6Prefixes = p.v6rib.AllPrefixes()
		p.v6rib = nil
	}
	p.mutex.Unlock()

	if len(v4Prefixes) > 0 {
		s.removeGlobalV4(v4Prefixes)
	}
	if len(v6Prefixes) > 0 {
		s.removeGlobalV6(v6Prefixes)
	}

	go func() {
		time.Sleep(5 * time.Second)
		log.Printf("Running FreeOSMemory after peer %s removal", p.ip)
		debug.FreeOSMemory()
		log.Printf("Memory cleanup complete after peer %s removal", p.ip)
	}()
}

func (s *Server) addGlobalV4(newPrefixes []netip.Prefix) {
	s.globalMasksMu.Lock()
	defer s.globalMasksMu.Unlock()
	for _, pfx := range newPrefixes {
		if s.v4PrefixRefs[pfx] == 0 {
			s.v4Masks[int32(pfx.Bits())]++
		}
		s.v4PrefixRefs[pfx]++
	}
}

func (s *Server) removeGlobalV4(removedPrefixes []netip.Prefix) {
	s.globalMasksMu.Lock()
	defer s.globalMasksMu.Unlock()
	for _, pfx := range removedPrefixes {
		if s.v4PrefixRefs[pfx] > 0 {
			s.v4PrefixRefs[pfx]--
			if s.v4PrefixRefs[pfx] == 0 {
				s.v4Masks[int32(pfx.Bits())]--
				delete(s.v4PrefixRefs, pfx)
			}
		}
	}
}

func (s *Server) addGlobalV6(newPrefixes []netip.Prefix) {
	s.globalMasksMu.Lock()
	defer s.globalMasksMu.Unlock()
	for _, pfx := range newPrefixes {
		if s.v6PrefixRefs[pfx] == 0 {
			s.v6Masks[int32(pfx.Bits())]++
		}
		s.v6PrefixRefs[pfx]++
	}
}

func (s *Server) removeGlobalV6(removedPrefixes []netip.Prefix) {
	s.globalMasksMu.Lock()
	defer s.globalMasksMu.Unlock()
	for _, pfx := range removedPrefixes {
		if s.v6PrefixRefs[pfx] > 0 {
			s.v6PrefixRefs[pfx]--
			if s.v6PrefixRefs[pfx] == 0 {
				s.v6Masks[int32(pfx.Bits())]--
				delete(s.v6PrefixRefs, pfx)
			}
		}
	}
}
