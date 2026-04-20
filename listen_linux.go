//go:build linux
// +build linux

package main

import (
	"context"
	"fmt"
	"log"
	"net"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

func (s *bgpWatchServer) listen(c config) {
	lc := net.ListenConfig{
		Control: func(network, address string, rc syscall.RawConn) error {
			var sockErr error
			err := rc.Control(func(fd uintptr) {
				// Detect socket family to determine how to pass peer addresses
				sa, err := unix.Getsockname(int(fd))
				if err != nil {
					sockErr = fmt.Errorf("getsockname failed: %w", err)
					return
				}
				isIPv6 := false
				if _, ok := sa.(*unix.SockaddrInet6); ok {
					isIPv6 = true
				}

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
						
						// Cap password length at 80 bytes (TCP_MD5SIG_MAXKEYLEN)
						key := peerConf.Password
						if len(key) > 80 {
							key = key[:80]
						}
						sig.Keylen = uint16(len(key))
						copy(sig.Key[:], key)

						if isIPv6 {
							// For IPv6 sockets (including dual-stack), we must use AF_INET6
							// and 16-byte addresses (IPv4-mapped if necessary).
							sig.Addr.Family = unix.AF_INET6
							sig.Prefixlen = 128
							raw := (*unix.RawSockaddrInet6)(unsafe.Pointer(&sig.Addr))
							raw.Family = unix.AF_INET6
							copy(raw.Addr[:], ip.To16())
						} else {
							// For IPv4-only sockets, we use AF_INET.
							ip4 := ip.To4()
							if ip4 == nil {
								// IPv6 peer on IPv4 socket is not possible
								continue
							}
							sig.Addr.Family = unix.AF_INET
							sig.Prefixlen = 32
							raw := (*unix.RawSockaddrInet4)(unsafe.Pointer(&sig.Addr))
							raw.Family = unix.AF_INET
							copy(raw.Addr[:], ip4)
						}

						// Apply to the socket
						err = unix.SetsockoptTCPMD5Sig(int(fd), unix.IPPROTO_TCP, unix.TCP_MD5SIG, &sig)
						if err != nil {
							sockErr = fmt.Errorf("failed to set TCP_MD5SIG for peer %s (keylen %d): %w", peerConf.IP, sig.Keylen, err)
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
