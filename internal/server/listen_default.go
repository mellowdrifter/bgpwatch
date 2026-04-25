//go:build !linux
// +build !linux

package server

import (
	"fmt"
	"log"
	"net"
)

func (s *Server) listen(c Config) {
	if c.PeersConfig != nil {
		for _, peerConf := range c.PeersConfig {
			if peerConf.Password != "" {
				log.Printf("Warning: TCP MD5 authentication for peer %s is not supported on this OS", peerConf.IP)
			}
		}
	}

	l, err := net.Listen("tcp", fmt.Sprintf(":%d", c.Port))
	if err != nil {
		log.Fatalf("Unable to start server: %v", err)
	}
	s.listener = l
	log.Printf("Listening on port %d (No MD5 support)\n", c.Port)
}
