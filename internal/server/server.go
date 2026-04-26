package server

import (
	"fmt"
	"log"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mellowdrifter/bgpwatch/internal/bgp"
	"github.com/mellowdrifter/routing_table"
)

type Server struct {
	listener     net.Listener
	peers        []*peer
	mutex        sync.RWMutex
	globalMasksMu sync.RWMutex
	v4Masks      map[int32]int32
	v6Masks      map[int32]int32
	v4PrefixRefs map[netip.Prefix]uint16
	v6PrefixRefs map[netip.Prefix]uint16
	Conf         Config
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
}

func New(conf Config) *Server {
	return &Server{
		mutex:        sync.RWMutex{},
		v4Masks:      make(map[int32]int32),
		v6Masks:      make(map[int32]int32),
		v4PrefixRefs: make(map[netip.Prefix]uint16),
		v6PrefixRefs: make(map[netip.Prefix]uint16),
		Conf:         conf,
	}
}

func (s *Server) Start() {
	s.listen(s.Conf)
	go s.clean()
	go s.startGRPC(s.Conf.GrpcPort)
	
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("%v\n", err)
		} else {
			peer := s.accept(conn)
			if peer != nil {
				go peer.peerWorker()
			}
		}
	}
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

	// If new client trying to connect with existing connection, remove old peer from pool
	for i, check := range s.peers {
		if ip == check.ip {
			check.conn.Close()
			s.peers = append(s.peers[:i], s.peers[i+1:]...)
			break
		}
	}

	peer := &peer{
		server:    s,
		conn:      conn,
		rid:       s.Conf.Rid,
		weor:      s.Conf.Eor,
		quiet:    s.Conf.Quiet,
		ip:        ip,
		mutex:     sync.RWMutex{},
		startTime: time.Now(),
		rib:       routing_table.GetNewRib(),
	}

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
	log.Printf("Removing dead peer %s\n", p.conn.RemoteAddr().String())

	s.mutex.Lock()
	for i, check := range s.peers {
		if check == p {
			s.peers = append(s.peers[:i], s.peers[i+1:]...)
			break
		}
	}
	s.mutex.Unlock()

	p.conn.Close()

	// Clean up global refs and peer's memory
	p.mutex.Lock()
	v4Prefixes := p.rib.AllPrefixesIPv4()
	v6Prefixes := p.rib.AllPrefixesIPv6()
	p.rib = routing_table.Rib{}
	p.mutex.Unlock()

	if len(v4Prefixes) > 0 {
		s.removeGlobalV4(v4Prefixes)
	}
	if len(v6Prefixes) > 0 {
		s.removeGlobalV6(v6Prefixes)
	}
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
