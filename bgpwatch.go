//watch will speak BGP and output adjustments to the BGP table, maybe output via streaming gRPC?
// RFC 4271 - BGP4
// Read 6793 to clarify - 4 byte ASN
// RFC 8092 - Large Communities
// RFC 2858 - MPBGP

package main

import (
	"bytes"
	"flag"
	"fmt"
	"log"
	"net"
	"net/netip"
	"os"

	"github.com/mellowdrifter/routing_table"
	"strconv"
	"strings"
	"sync"
	"time"
)

type bgpWatchServer struct {
	listener net.Listener
	peers    []*peer
	mutex    sync.RWMutex
	rib      routing_table.Rib
	conf     config
}

type config struct {
	rid               bgpid
	port              int
	grpcPort          int
	logfile           string
	eor               bool
	quiet             bool
	ignoreCommunities bool
}

func main() {

	srid := flag.String("rid", "0.0.0.1", "router id")
	logs := flag.String("log", "", "log location, stdout if not given")
	port := flag.Int("port", 179, "listen port")
	grpcPort := flag.Int("grpc", 1179, "gRPC listen port")
	weor := flag.Bool("endofrib", false, "log updates only when EoR received")
	quiet := flag.Bool("quiet", false, "suppress per-update logging, show only periodic stats")
	ignoreComms := flag.Bool("ignore-communities", false, "ignore and discard BGP communities and large communities")
	flag.Parse()
	conf := getConfig(srid, logs, port, grpcPort, weor, quiet, ignoreComms)

	// Set up log file
	if conf.logfile != "" {
		f, err := os.OpenFile(conf.logfile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			log.Fatalf("failed to open logfile: %v", err)
		}
		defer f.Close()
		log.SetOutput(f)
	} else {
		log.SetOutput(os.Stdout)
	}

	// Start server
	serv := bgpWatchServer{
		mutex: sync.RWMutex{},
		rib:   routing_table.GetNewRib(),
		conf:  conf,
	}
	serv.listen(conf)
	go serv.clean()
	go serv.startGRPC(conf.grpcPort)
	serv.start(conf)
}

func getConfig(srid, logf *string, port, grpcPort *int, eor, quiet, ignoreComms *bool) config {
	rid, err := getRid(srid)
	if err != nil {
		log.Fatalf("Unable to convert %s to RID format: %v", *srid, err)
	}

	return config{
		rid:               rid,
		port:              *port,
		grpcPort:          *grpcPort,
		logfile:           *logf,
		eor:               *eor,
		quiet:             *quiet,
		ignoreCommunities: *ignoreComms,
	}
}

// Convert the string RID to actual RID.
func getRid(srid *string) (bgpid, error) {
	s := strings.Split(*srid, ".")
	var rid bgpid
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

// Start listening
func (s *bgpWatchServer) listen(c config) {
	l, err := net.Listen("tcp", fmt.Sprintf(":%d", c.port))
	if err != nil {
		log.Fatalf("Unable to start server: %v", err)
	}
	s.listener = l
	log.Printf("Listening on port %d\n", c.port)

}

// start will start the listener as well as start each peer worker.
func (s *bgpWatchServer) start(conf config) {
	for {
		conn, err := s.listener.Accept()
		if err != nil {
			log.Printf("%v\n", err)
		} else {
			peer := s.accept(conn, conf)
			go peer.peerWorker()
		}
	}
}

// clean checks for and removes stale clients that haven't sent a keepalive within their holdtime.
func (s *bgpWatchServer) clean() {
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
			// Closing connection will cause getMessage in peerWorker to error and return,
			// which then triggers the deferred p.server.remove(p).
			p.conn.Close()
		}
	}
}

// accept adds a new client to the current list of clients being served.
func (s *bgpWatchServer) accept(conn net.Conn, c config) *peer {
	log.Printf("Connection from %v, total peers: %d\n",
		conn.RemoteAddr().String(), len(s.peers)+1)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// If new client trying to connect with existing connection, remove old peer from pool
	for i, check := range s.peers {
		if ip == check.ip {
			check.conn.Close()
			s.peers = append(s.peers[:i], s.peers[i+1:]...)
			break
		}
	}

	// Each client will have a buffer with the maximum BGP message size. This is only
	// 4k per client, so it's not a big deal.
	peer := &peer{
		server:    s,
		conn:      conn,
		rid:       c.rid,
		weor:      c.eor,
		quiet:    c.quiet,
		ip:        ip,
		out:       bytes.NewBuffer(make([]byte, 4096)),
		mutex:     sync.RWMutex{},
		startTime: time.Now(),
		rib:       routing_table.GetNewRib(),
		prefixSet: make(map[netip.Prefix]struct{}),
	}

	s.peers = append(s.peers, peer)

	log.Printf("New peer added to list: %+v\n", s.peers)

	return peer
}

// remove removes a client from the current list of clients being served.
func (s *bgpWatchServer) remove(p *peer) {
	log.Printf("Removing dead peer %s\n", p.conn.RemoteAddr().String())

	s.mutex.Lock()
	defer s.mutex.Unlock()

	// remove the connection from client array
	for i, check := range s.peers {
		if check == p {
			s.peers = append(s.peers[:i], s.peers[i+1:]...)
			break
		}
	}
	// Don't worry about errors as it's mostly because it's already closed.
	p.conn.Close()

	// Batch delete unique prefixes from the global RIB
	var v4Del []netip.Prefix
	var v6Del []netip.Prefix

	p.mutex.RLock()
	for prefix := range p.prefixSet {
		if !s.isHeldByOtherPeerLocked(prefix, p) {
			if prefix.Addr().Is4() {
				v4Del = append(v4Del, prefix)
			} else {
				v6Del = append(v6Del, prefix)
			}
		}
	}
	p.mutex.RUnlock()

	if len(v4Del) > 0 {
		s.rib.DeleteIPv4Batch(v4Del)
	}
	if len(v6Del) > 0 {
		s.rib.DeleteIPv6Batch(v6Del)
	}

	// Clean up peer's memory
	p.mutex.Lock()
	p.prefixSet = nil
	p.rib = routing_table.Rib{}
	p.mutex.Unlock()
}

// isHeldByOtherPeerLocked checks if any peer other than the excluded one holds the prefix.
// MUST be called with s.mutex held (at least RLock).
func (s *bgpWatchServer) isHeldByOtherPeerLocked(prefix netip.Prefix, exclude *peer) bool {
	for _, p := range s.peers {
		if p == exclude {
			continue
		}
		p.mutex.RLock()
		_, exists := p.prefixSet[prefix]
		p.mutex.RUnlock()
		if exists {
			return true
		}
	}
	return false
}
