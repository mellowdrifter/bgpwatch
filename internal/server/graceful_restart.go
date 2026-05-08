package server

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"sync"
	"time"

	"github.com/mellowdrifter/bgpwatch/internal/bgp"
)

// PeerStatus defines the atomic state values for the Graceful Restart state machine.
type PeerStatus uint32

const (
	StatusEstablished PeerStatus = iota
	StatusGRStale
	StatusWaitingForEOR
	StatusPurging
	StatusPurgingRemainingStale
)

func (s PeerStatus) String() string {
	switch s {
	case StatusEstablished:
		return "Established"
	case StatusGRStale:
		return "GR Stale"
	case StatusWaitingForEOR:
		return "Waiting for EoR"
	case StatusPurging:
		return "Purging"
	case StatusPurgingRemainingStale:
		return "Purging Remaining Stale"
	default:
		return "Unknown"
	}
}

type Family struct {
	AFI  uint16
	SAFI uint8
}

// GracefulRestartManager defines the interface for managing BGP Graceful Restart
// state transitions for the receiving speaker (helper mode).
type GracefulRestartManager interface {
	HandlePeerDown(ctx context.Context, peerIP string) error
	ProcessCapExchange(ctx context.Context, peerIP string, params bgp.Parameters) error
	ReceiveEoR(ctx context.Context, peerIP string, family Family) error
	CompleteGracefulRestart(ctx context.Context, peerIP string) error
}

type defaultGRManager struct {
	server           *Server
	restartTime      time.Duration
	fallbackDuration time.Duration
	eorReceived      map[string]map[Family]bool
	mu               sync.Mutex
}

// NewGracefulRestartManager creates a new instance of the default GR manager.
func NewGracefulRestartManager(s *Server) GracefulRestartManager {
	rt := s.Conf.GRRestartTime
	if rt == 0 {
		rt = 15 * time.Minute
	}
	fb := s.Conf.GREoRFallbackTime
	if fb == 0 {
		fb = 15 * time.Minute
	}

	return &defaultGRManager{
		server:           s,
		restartTime:      rt,
		fallbackDuration: fb,
		eorReceived:      make(map[string]map[Family]bool),
	}
}

// SetTimersForTest allows modifying the hardcoded timers in integration tests.
func (m *defaultGRManager) SetTimersForTest(restart, fallback time.Duration) {
	m.restartTime = restart
	m.fallbackDuration = fallback
}

func (m *defaultGRManager) getPeer(ip string) (*peer, bool) {
	m.server.mutex.RLock()
	defer m.server.mutex.RUnlock()

	for _, p := range m.server.peers {
		if p.ip == ip {
			return p, true
		}
	}
	return nil, false
}

func (m *defaultGRManager) ProcessCapExchange(ctx context.Context, peerIP string, params bgp.Parameters) error {
	p, ok := m.getPeer(peerIP)
	if !ok {
		return fmt.Errorf("peer not found: %s", peerIP)
	}

	// Always initialize EoR map and stop existing timers if we are in this flow
	m.mu.Lock()
	m.eorReceived[peerIP] = make(map[Family]bool)
	m.mu.Unlock()

	p.mutex.Lock()
	if p.restartTimer != nil {
		p.restartTimer.Stop()
		p.restartTimer = nil
	}
	if p.eorFallbackTimer != nil {
		p.eorFallbackTimer.Stop()
		p.eorFallbackTimer = nil
	}

	if params.GRCapability == nil && !p.weor {
		p.status.Store(uint32(StatusPurging))
		p.mutex.Unlock()
		return m.purgeAllStalePaths(ctx, p)
	}

	p.status.Store(uint32(StatusWaitingForEOR))

	p.eorFallbackTimer = time.AfterFunc(m.fallbackDuration, func() {
		if PeerStatus(p.status.Load()) == StatusWaitingForEOR {
			p.status.Store(uint32(StatusPurgingRemainingStale))
			log.Printf("EoR fallback timer expired for peer %s", peerIP)
			_ = m.CompleteGracefulRestart(context.Background(), peerIP)
		}
	})
	p.mutex.Unlock()

	return nil
}

func (m *defaultGRManager) ReceiveEoR(ctx context.Context, peerIP string, family Family) error {
	p, ok := m.getPeer(peerIP)
	if !ok {
		return fmt.Errorf("peer not found: %s", peerIP)
	}

	m.mu.Lock()
	if _, ok := m.eorReceived[peerIP]; !ok {
		m.eorReceived[peerIP] = make(map[Family]bool)
	}
	m.eorReceived[peerIP][family] = true
	received := m.eorReceived[peerIP]
	m.mu.Unlock()

	// Check if we received EoR for all negotiated families
	p.mutex.RLock()
	negotiated := p.param.AddrFamilies
	p.mutex.RUnlock()

	allReceived := true
	for _, f := range negotiated {
		fam := Family{AFI: f.AFI, SAFI: f.SAFI}
		if !received[fam] {
			allReceived = false
			break
		}
	}

	// If no families negotiated (legacy IPv4), check against a default Family{1, 1}
	if len(negotiated) == 0 {
		if !received[Family{1, 1}] {
			allReceived = false
		}
	}

	if allReceived {
		log.Printf("All EoRs received for peer %s, triggering purge", peerIP)
		return m.CompleteGracefulRestart(ctx, peerIP)
	}

	log.Printf("Received EoR for peer %s family %+v, still waiting for others", peerIP, family)
	return nil
}

func (m *defaultGRManager) HandlePeerDown(ctx context.Context, peerIP string) error {
	p, ok := m.getPeer(peerIP)
	if !ok {
		return fmt.Errorf("peer not found: %s", peerIP)
	}

	p.mutex.Lock()
	// If already in GRStale state, don't reset the timer (prevent flap extension)
	if PeerStatus(p.status.Load()) == StatusGRStale && p.restartTimer != nil {
		p.mutex.Unlock()
		log.Printf("Peer %s down again, but already in GR_STALE, keeping original timer", peerIP)
		return nil
	}

	p.status.Store(uint32(StatusGRStale))

	p.restartTimer = time.AfterFunc(m.restartTime, func() {
		if PeerStatus(p.status.Load()) == StatusGRStale {
			p.status.Store(uint32(StatusPurging))
			log.Printf("Restart timer expired for peer %s, purging stale routes", peerIP)
			_ = m.CompleteGracefulRestart(context.Background(), peerIP)
		}
	})
	p.mutex.Unlock()

	log.Printf("Peer %s down, entered GR_STALE state (15m timer started)", peerIP)
	return nil
}

func (m *defaultGRManager) CompleteGracefulRestart(ctx context.Context, peerIP string) error {
	p, ok := m.getPeer(peerIP)
	if !ok {
		return fmt.Errorf("peer not found: %s", peerIP)
	}

	p.mutex.Lock()
	if p.eorFallbackTimer != nil {
		p.eorFallbackTimer.Stop()
		p.eorFallbackTimer = nil
	}
	if p.restartTimer != nil {
		p.restartTimer.Stop()
		p.restartTimer = nil
	}
	p.mutex.Unlock()

	m.mu.Lock()
	delete(m.eorReceived, peerIP)
	m.mu.Unlock()

	return m.purgeAllStalePaths(ctx, p)
}

func (m *defaultGRManager) purgeAllStalePaths(ctx context.Context, p *peer) error {
	log.Printf("Purging all stale paths for peer %s", p.ip)

	var removedV4, removedV6 []netip.Prefix
	if p.v4rib != nil {
		removedV4 = p.v4rib.DeleteStaleRoutes()
	}
	if p.v6rib != nil {
		removedV6 = p.v6rib.DeleteStaleRoutes()
	}

	if len(removedV4) > 0 {
		m.server.removeGlobalV4(removedV4)
	}
	if len(removedV6) > 0 {
		m.server.removeGlobalV6(removedV6)
	}

	p.status.Store(uint32(StatusEstablished))
	p.mutex.Lock()
	p.staleSince = time.Time{}
	p.mutex.Unlock()
	log.Printf("Purge complete for peer %s: removed %d v4, %d v6 prefixes",
		p.ip, len(removedV4), len(removedV6))
	return nil
}
