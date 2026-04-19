//go:build linux
// +build linux

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"syscall"

	"golang.org/x/sys/unix"
)

func (s *bgpWatchServer) listen(c config) {
	lc := net.ListenConfig{
		Control: func(network, address string, rc syscall.RawConn) error {
			var sockErr error
			err := rc.Control(func(fd uintptr) {
				// Apply TCP MD5 option for each peer that has a password
				if c.peersConfig != nil {
					for _, peerConf := range c.peersConfig {
						if peerConf.Password == "" {
							continue
						}

						ip := net.ParseIP(peerConf.IP)
						if ip == nil {
							log.Printf("Warning: Invalid IP address %s in config", peerConf.IP)
							continue
						}

						var sig unix.TCPMD5Sig
						sig.Keylen = uint16(len(peerConf.Password))
						copy(sig.Key[:], peerConf.Password)

						if ip4 := ip.To4(); ip4 != nil {
							sig.Addr.Family = unix.AF_INET
							// In SockaddrStorage, Data[0:4] contains the IP address for AF_INET (after Family)
							// Actually, to be safe, we cast it from SockaddrInet4
							sa := &unix.SockaddrInet4{Port: 0}
							copy(sa.Addr[:], ip4)
							// We can't directly cast to SockaddrStorage, but we can set the bytes
							// For AF_INET, the layout is: Family (uint16), Port (uint16, network byte order), Addr (4 bytes)
							// In SockaddrStorage: Data starts at index 0 after Family.
							// Port is Data[0:2], Addr is Data[2:6]
							copy(sig.Addr.Data[2:6], ip4)
						} else {
							sig.Addr.Family = unix.AF_INET6
							// For AF_INET6: Port is Data[0:2], Flowinfo is Data[2:6], Addr is Data[6:22]
							copy(sig.Addr.Data[6:22], ip)
						}

						// Apply to the socket
						err := unix.SetsockoptTCPMD5Sig(int(fd), unix.IPPROTO_TCP, unix.TCP_MD5SIG, &sig)
						if err != nil {
							sockErr = fmt.Errorf("failed to set TCP_MD5SIG for peer %s: %w", peerConf.IP, err)
						}
					}
				}
			})
			if sockErr != nil {
				return sockErr
			}
			return err
		},
	}

	// Disable MPTCP as it is incompatible with TCP_MD5SIG
	lc.SetMultipathTCP(false)

	l, err := lc.Listen(context.Background(), "tcp", fmt.Sprintf(":%d", c.port))
	if err != nil {
		log.Fatalf("Unable to start server: %v", err)
	}
	s.listener = l
	log.Printf("Listening on port %d (Linux with MD5 support)\n", c.port)
}
