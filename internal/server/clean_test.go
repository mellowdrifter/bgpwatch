package server

import (
	"io"
	"net"
	"testing"
	"time"
)

func newCleanTestPeer(t *testing.T, ip string, status PeerStatus) (*peer, net.Conn) {
	t.Helper()
	local, remote := net.Pipe()
	// Drain whatever the server writes so net.Pipe writes don't block.
	go io.Copy(io.Discard, remote)
	t.Cleanup(func() { local.Close(); remote.Close() })

	p := &peer{
		ip:            ip,
		conn:          local,
		holdtime:      1,
		lastKeepalive: time.Now().Add(-time.Hour), // long past holdtime
	}
	p.status.Store(uint32(status))
	return p, remote
}

// A GR_STALE peer is already disconnected and being held for resync. The hold
// timer cleaner must leave it alone and not clobber its real disconnect cause.
func TestCleanOnceSkipsStalePeer(t *testing.T) {
	p, _ := newCleanTestPeer(t, "192.0.2.1", StatusGRStale)
	s := &Server{
		peers:     []*peer{p},
		peerStats: map[string]*persistentPeerStats{p.ip: {lastNotification: "6 / 4"}},
	}

	s.cleanOnce()

	if got := s.peerStats[p.ip].lastNotification; got != "6 / 4" {
		t.Errorf("lastNotification overwritten for stale peer: got %q", got)
	}
	// Conn must not have been closed by the cleaner.
	p.conn.SetWriteDeadline(time.Now().Add(time.Second))
	if _, err := p.conn.Write([]byte{0}); err != nil {
		t.Errorf("stale peer conn was closed by cleaner: %v", err)
	}
}

// A live peer that has stopped sending keepalives must still be dropped.
func TestCleanOnceDropsExpiredPeer(t *testing.T) {
	p, _ := newCleanTestPeer(t, "192.0.2.2", StatusEstablished)
	s := &Server{
		peers:     []*peer{p},
		peerStats: map[string]*persistentPeerStats{},
	}

	s.cleanOnce()

	if got := s.peerStats[p.ip].lastNotification; got != "HOLD TIMER" {
		t.Errorf("lastNotification = %q, want HOLD TIMER", got)
	}
	if _, err := p.conn.Write([]byte{0}); err == nil {
		t.Error("expired peer conn should have been closed")
	}
}
