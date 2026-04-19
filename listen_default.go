//go:build !linux
// +build !linux

package main

import (
	"fmt"
	"log"
	"net"
)

func (s *bgpWatchServer) listen(c config) {
	if c.peersConfig != nil {
		for _, peerConf := range c.peersConfig {
			if peerConf.Password != "" {
				log.Printf("Warning: TCP MD5 authentication for peer %s is not supported on this OS", peerConf.IP)
			}
		}
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", c.port))
	if err != nil {
		log.Fatalf("Unable to start server: %v", err)
	}
	s.listener = l
	log.Printf("Listening on port %d (No MD5 support)\n", c.port)
}
