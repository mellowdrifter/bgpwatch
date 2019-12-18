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
	"os"
	"strconv"
	"strings"
	"sync"
	"time"
)

type bgpWatchServer struct {
	listener net.Listener
	peers    []*peer
	mutex    sync.RWMutex
}

type config struct {
	rid     bgpid
	port    int
	logfile string
	eor     bool
}

func main() {

	srid := flag.String("rid", "0.0.0.1", "router id")
	logs := flag.String("log", "", "log location, stdout if not given")
	port := flag.Int("port", 179, "listen port")
	weor := flag.Bool("endofrib", false, "log updates only when EoR received")
	flag.Parse()
	conf := getConfig(srid, logs, port, weor)

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
	}
	serv.listen(conf)
	go serv.clean()
	serv.start(conf)
}

func getConfig(srid, logf *string, port *int, eor *bool) config {
	rid, err := getRid(srid)
	if err != nil {
		log.Fatalf("Unable to convert %s to RID format: %v", *srid, err)
	}

	return config{
		rid:     rid,
		port:    *port,
		logfile: *logf,
		eor:     *eor,
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

// TODO: Make this work, and remove old clients
func (s *bgpWatchServer) clean() {
	time.Sleep(5 * time.Second)
	log.Printf("I have %d clients connected\n", len(s.peers))
}

// accept adds a new client to the current list of clients being served.
func (s *bgpWatchServer) accept(conn net.Conn, c config) *peer {
	log.Printf("Connection from %v, total peers: %d\n",
		conn.RemoteAddr().String(), len(s.peers)+1)

	s.mutex.Lock()
	defer s.mutex.Unlock()

	ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())

	// If new client trying to connect with existing connection, remove old peer from pool
	for _, peer := range s.peers {
		if ip == peer.ip {
			s.remove(peer)
			break
		}
	}

	// Each client will have a buffer with the maximum BGP message size. This is only
	// 4k per client, so it's not a big deal.
	peer := &peer{
		conn:      conn,
		rid:       c.rid,
		weor:      c.eor,
		ip:        ip,
		out:       bytes.NewBuffer(make([]byte, 4096)),
		mutex:     sync.RWMutex{},
		startTime: time.Now(),
	}

	s.peers = append(s.peers, peer)

	log.Printf("New peer added to list: %+v\n", s.peers)

	return peer
}

// remove removes a client from the current list of clients being served.
func (s *bgpWatchServer) remove(p *peer) {
	log.Printf("Removing dead peer %s\n", p.conn.RemoteAddr().String())

	// remove the connection from client array
	for i, check := range s.peers {
		if check == p {
			s.peers = append(s.peers[:i], s.peers[i+1:]...)
		}
	}
	// Don't worry about errors as it's mostly because it's already closed.
	p.conn.Close()

}
