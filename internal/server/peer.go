package server

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"runtime/debug"
	"sync"
	"sync/atomic"
	"time"

	"github.com/mellowdrifter/bgpwatch/internal/bgp"
	"github.com/mellowdrifter/routing_table"
)

var (
	bgpMarker = []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}

	standardPool = sync.Pool{
		New: func() interface{} {
			return new([bgp.MaxMessage]byte)
		},
	}
	extendedPool = sync.Pool{
		New: func() interface{} {
			return new([bgp.MaxExtendedMessage]byte)
		},
	}
)

type peer struct {
	server          *Server
	peerAsn         uint32
	isIBGP          bool
	holdtime        uint16
	ip              string
	conn            net.Conn
	v4eor           bool
	v6eor           bool
	weor            bool
	quiet           bool
	mutex           sync.RWMutex
	param           bgp.Parameters
	rid             bgp.BGPID
	keepalives      uint64
	lastKeepalive   time.Time
	updates         uint64
	withdraws       uint64
	startTime       time.Time
	establishedTime time.Time
	in              *bytes.Reader
	prefixes         *bgp.PrefixAttributes
	v4rib            *routing_table.IPv4Rib
	v6rib            *routing_table.IPv6Rib
	status           atomic.Uint32
	staleSince       time.Time
	restartTimer     *time.Timer
	eorFallbackTimer *time.Timer
	msgRecv          uint64
	inUpdates        uint64
	memCleanupOnce   sync.Once
}

func (p *peer) peerWorker() {
	defer p.server.remove(p)
	for {
		maxLen := uint16(bgp.MaxMessage)
		if p.param.ExtendedMessage {
			maxLen = bgp.MaxExtendedMessage
		}

		msg, stdBuf, extBuf, err := p.getMessage(maxLen)
		if err != nil {
			log.Printf("Bad BGP message from %s: %v\n", p.ip, err)
			p.conn.Close()
			return
		}

		if p.in == nil {
			p.in = bytes.NewReader(msg)
		} else {
			p.in.Reset(msg)
		}
		p.mutex.Lock()
		p.msgRecv++
		p.mutex.Unlock()

		header, err := p.getType()
		if err != nil {
			log.Printf("Unable to decode header: %v\n", err)
			p.conn.Close()
			return
		}

		switch header {
		case bgp.Open:
			if err := p.HandleOpen(); err != nil {
				log.Printf("Error handling Open: %v\n", err)
				p.conn.Close()
				return
			}
			p.conn.Write(bgp.CreateOpen(p.server.Conf.Asn, p.holdtime, p.rid, &p.param))

		case bgp.Keepalive:
			if err := p.HandleKeepalive(); err != nil {
				log.Printf("Error handling Keepalive: %v\n", err)
				p.conn.Close()
				return
			}
			p.conn.Write(bgp.CreateKeepAlive())

		case bgp.Update:
			p.mutex.Lock()
			p.inUpdates++
			p.mutex.Unlock()
			if err := p.handleUpdate(); err != nil {
				log.Printf("Error handling Update: %v\n", err)
				p.conn.Close()
				return
			}
			p.logUpdate()

		case bgp.Notification:
			if err := p.handleNotification(); err != nil {
				log.Printf("Error handling Notification: %v\n", err)
				p.conn.Close()
			}
			return

		default:
			log.Printf("Unknown BGP message inbound from %s: %d\n", p.ip, header)
		}

		// Return buffer to pool after processing is complete and no references remain
		if stdBuf != nil {
			standardPool.Put(stdBuf)
		} else if extBuf != nil {
			extendedPool.Put(extBuf)
		}
	}
}

func (p *peer) getMessage(maxLen uint16) ([]byte, *[bgp.MaxMessage]byte, *[bgp.MaxExtendedMessage]byte, error) {
	stdBuf := standardPool.Get().(*[bgp.MaxMessage]byte)

	// Read header (19 bytes: 16 marker, 2 length, 1 type)
	if _, err := io.ReadFull(p.conn, stdBuf[:19]); err != nil {
		standardPool.Put(stdBuf)
		return nil, nil, nil, err
	}

	// Validate marker
	if !bytes.Equal(stdBuf[:16], bgpMarker) {
		standardPool.Put(stdBuf)
		return nil, nil, nil, fmt.Errorf("packet is not a BGP packet")
	}

	msgLen := int(binary.BigEndian.Uint16(stdBuf[16:18]))
	if msgLen < bgp.MinMessage || msgLen > int(maxLen) {
		standardPool.Put(stdBuf)
		return nil, nil, nil, fmt.Errorf("invalid BGP message length: %d (max: %d)", msgLen, maxLen)
	}

	if msgLen <= bgp.MaxMessage {
		// Read the rest of the message
		if _, err := io.ReadFull(p.conn, stdBuf[19:msgLen]); err != nil {
			standardPool.Put(stdBuf)
			return nil, nil, nil, err
		}
		// Return slice starting at index 18 (Type byte) for compatibility with p.getType()
		return stdBuf[18:msgLen], stdBuf, nil, nil
	}

	// Extended message handling
	extBuf := extendedPool.Get().(*[bgp.MaxExtendedMessage]byte)
	copy(extBuf[:19], stdBuf[:19])
	standardPool.Put(stdBuf)

	if _, err := io.ReadFull(p.conn, extBuf[19:msgLen]); err != nil {
		extendedPool.Put(extBuf)
		return nil, nil, nil, err
	}
	// Return slice starting at index 18 (Type byte)
	return extBuf[18:msgLen], nil, extBuf, nil
}

// getMessage is deprecated, use p.getMessage()

func (p *peer) getType() (uint8, error) {
	var t uint8
	if err := binary.Read(p.in, binary.BigEndian, &t); err != nil {
		return 0, err
	}
	return t, nil
}

func (p *peer) HandleKeepalive() error {
	p.mutex.Lock()
	p.keepalives++
	p.lastKeepalive = time.Now()
	p.mutex.Unlock()
	return nil
}

func (p *peer) HandleOpen() error {
	log.Printf("Received Open Message from %s", p.ip)

	var version uint8
	if err := binary.Read(p.in, binary.BigEndian, &version); err != nil {
		return err
	}
	if version != 4 {
		return fmt.Errorf("unsupported BGP version: %d", version)
	}

	var asn16 uint16
	if err := binary.Read(p.in, binary.BigEndian, &asn16); err != nil {
		return err
	}

	var holdtime uint16
	if err := binary.Read(p.in, binary.BigEndian, &holdtime); err != nil {
		return err
	}

	var rid bgp.BGPID
	if err := binary.Read(p.in, binary.BigEndian, &rid); err != nil {
		return err
	}

	var paramLen uint8
	if err := binary.Read(p.in, binary.BigEndian, &paramLen); err != nil {
		return err
	}

	pbuffer := make([]byte, int(paramLen))
	if _, err := io.ReadFull(p.in, pbuffer); err != nil {
		return err
	}

	params, err := bgp.DecodeOptionalParameters(&pbuffer)
	if err != nil {
		return err
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	p.peerAsn = uint32(asn16)
	p.holdtime = holdtime
	p.param = params

	// Check for 32-bit ASN capability
	emptyASN := [4]byte{}
	if !bytes.Equal(params.ASN32[:], emptyASN[:]) {
		p.peerAsn = binary.BigEndian.Uint32(params.ASN32[:])
	}

	if p.peerAsn == p.server.Conf.Asn {
		p.isIBGP = true
		log.Printf("iBGP session established with peer %s (AS %d)\n", p.ip, p.peerAsn)
	} else {
		p.isIBGP = false
		log.Printf("eBGP session established with peer %s (AS %d)\n", p.ip, p.peerAsn)
	}

	if p.establishedTime.IsZero() {
		p.establishedTime = time.Now()
	}

	// Initialize RIBs based on negotiated capabilities
	v4 := false
	v6 := false
	for _, f := range p.param.AddrFamilies {
		if f.AFI == 1 {
			v4 = true
		} else if f.AFI == 2 {
			v6 = true
		}
	}
	for _, f := range p.param.AddPath {
		if f.AFI == 1 {
			v4 = true
		} else if f.AFI == 2 {
			v6 = true
		}
	}
	// If no MP-BGP or Add-Path caps, it defaults to IPv4 (legacy)
	if !v4 && !v6 {
		v4 = true
	}

	if v4 && p.v4rib == nil {
		p.v4rib = routing_table.NewIPv4Rib(p.server.v4AttrTable)
	}
	if v6 && p.v6rib == nil {
		p.v6rib = routing_table.NewIPv6Rib(p.server.v6AttrTable)
	}

	// All sessions transition to WaitingForEOR state during capability exchange
	p.status.Store(uint32(StatusWaitingForEOR))
	go func() {
		if err := p.server.grManager.ProcessCapExchange(context.Background(), p.ip, p.param); err != nil {
			log.Printf("GR ProcessCapExchange error for %s: %v", p.ip, err)
		}
	}()

	return nil
}

func (p *peer) handleNotification() error {
	var code uint8
	if err := binary.Read(p.in, binary.BigEndian, &code); err != nil {
		return fmt.Errorf("reading notification code: %w", err)
	}
	var subcode uint8
	if err := binary.Read(p.in, binary.BigEndian, &subcode); err != nil {
		return fmt.Errorf("reading notification subcode: %w", err)
	}
	log.Printf("Notification received from %s: code %d, subcode %d\n", p.ip, code, subcode)
	p.server.mutex.Lock()
	if _, ok := p.server.peerStats[p.ip]; !ok {
		p.server.peerStats[p.ip] = &persistentPeerStats{}
	}
	p.server.peerStats[p.ip].lastNotification = fmt.Sprintf("%d / %d", code, subcode)
	p.server.mutex.Unlock()
	return nil
}

func (p *peer) handleUpdate() error {
	var pa bgp.PrefixAttributes

	v4AddPath := false
	v6AddPath := false
	for _, a := range p.param.AddPath {
		if a.AFI == 1 && a.SAFI == 1 && (a.SendReceive&2) != 0 {
			v4AddPath = true
		}
		if a.AFI == 2 && a.SAFI == 1 && (a.SendReceive&2) != 0 {
			v6AddPath = true
		}
	}

	var withdraw uint16
	if err := binary.Read(p.in, binary.BigEndian, &withdraw); err != nil {
		return err
	}

	if withdraw != 0 {
		wbuf := make([]byte, withdraw)
		if _, err := io.ReadFull(p.in, wbuf); err != nil {
			return err
		}
		wd, err := bgp.DecodeIPv4Withdraws(wbuf, v4AddPath)
		if err != nil {
			return err
		}
		pa.V4Withdraws = wd.V4Withdraws
	}

	var attrLength uint16
	if err := binary.Read(p.in, binary.BigEndian, &attrLength); err != nil {
		return err
	}

	if withdraw == 0 && attrLength == 0 {
		p.mutex.Lock()
		p.v4eor = true
		pa.V4EoR = true
		p.prefixes = &pa
		p.mutex.Unlock()
		p.processRibUpdates()
		return nil
	}

	if attrLength == 0 {
		p.mutex.Lock()
		p.prefixes = &pa
		p.mutex.Unlock()
		p.processRibUpdates()
		return nil
	}

	abuf := make([]byte, attrLength)
	if _, err := io.ReadFull(p.in, abuf); err != nil {
		return err
	}

	attr, err := bgp.DecodePathAttributes(abuf, v6AddPath, p.server.Conf.IgnoreCommunities)
	if err != nil {
		return err
	}
	pa.Attr = attr

	if p.in.Len() > 0 {
		v4prefixes, err := bgp.DecodeIPv4NLRI(p.in, v4AddPath)
		if err != nil {
			return err
		}
		pa.V4prefixes = v4prefixes
	}

	if pa.Attr != nil {
		pa.V4NextHop = pa.Attr.NextHopv4
		pa.V6prefixes = pa.Attr.Ipv6NLRI
		pa.V6NextHops = pa.Attr.NextHopsv6
		pa.V6EoR = pa.Attr.V6EoR
		pa.V6Withdraws = pa.Attr.V6Withdraws
	}

	p.mutex.Lock()
	if pa.V4EoR {
		p.v4eor = true
	}
	if pa.V6EoR {
		p.v6eor = true
	}
	p.prefixes = &pa
	p.mutex.Unlock()

	p.processRibUpdates()
	return nil
}

func (p *peer) logUpdate() {
	if p.weor && !(p.v4eor || p.v6eor) {
		p.mutex.Lock()
		p.prefixes = nil
		p.mutex.Unlock()
		return
	}

	if p.quiet {
		p.mutex.Lock()
		p.prefixes = nil
		p.mutex.Unlock()
		return
	}

	log.Println("----------------------")
	p.mutex.RLock()
	if p.prefixes == nil {
		p.mutex.RUnlock()
		return
	}

	if len(p.prefixes.V4prefixes) > 0 {
		log.Printf("Received %d IPv4 prefixes from %s", len(p.prefixes.V4prefixes), p.ip)
		for _, prefix := range p.prefixes.V4prefixes {
			if prefix.ID != 0 {
				log.Printf("%v/%d (Path ID %d)\n", prefix.Prefix, prefix.Mask, prefix.ID)
			} else {
				log.Printf("%v/%d\n", prefix.Prefix, prefix.Mask)
			}
		}
		if p.prefixes.V4NextHop != "" {
			log.Printf("With next-hop: %s", p.prefixes.V4NextHop)
		}
	}

	if len(p.prefixes.V6prefixes) > 0 {
		log.Printf("Received %d IPv6 prefixes from %s", len(p.prefixes.V6prefixes), p.ip)
		for _, prefix := range p.prefixes.V6prefixes {
			if prefix.ID != 0 {
				log.Printf("%v/%d (Path ID %d)\n", prefix.Prefix, prefix.Mask, prefix.ID)
			} else {
				log.Printf("%v/%d\n", prefix.Prefix, prefix.Mask)
			}
		}
		log.Printf("With next-hops: %v", p.prefixes.V6NextHops)
	}

	if p.prefixes.Attr != nil {
		log.Printf("Origin: %s\n", p.prefixes.Attr.Origin.String())
		if len(p.prefixes.Attr.Aspath) > 0 {
			log.Printf("AS-path: %s\n", bgp.FormatASPath(&p.prefixes.Attr.Aspath))
		}
		if p.prefixes.Attr.LocalPref != 0 {
			log.Printf("Local Preference: %d\n", p.prefixes.Attr.LocalPref)
		}
		if len(p.prefixes.Attr.Communities) > 0 {
			log.Printf("Communities: %s\n", bgp.FormatCommunities(&p.prefixes.Attr.Communities))
		}
		if len(p.prefixes.Attr.LargeCommunities) > 0 {
			log.Printf("Large Communities: %s\n", bgp.FormatLargeCommunities(&p.prefixes.Attr.LargeCommunities))
		}
	}

	if p.prefixes.V4EoR {
		log.Printf("IPv4 End-of-Rib received from %s", p.ip)
		p.v4eor = true
	}
	if p.prefixes.V6EoR {
		log.Printf("IPv6 End-of-Rib received from %s", p.ip)
		p.v6eor = true
	}

	p.mutex.RUnlock()

	// Empty out the prefixes field
	p.mutex.Lock()
	p.prefixes = nil
	p.mutex.Unlock()
}

func mapAttributes(pa *bgp.PathAttr) *routing_table.RouteAttributes {
	if pa == nil {
		return &routing_table.RouteAttributes{}
	}

	ra := &routing_table.RouteAttributes{
		LocalPref: pa.LocalPref,
	}

	for _, seg := range pa.Aspath {
		if seg.Type == 2 { // AS_SEQUENCE
			ra.AsPath = append(ra.AsPath, seg.ASN)
		}
	}

	for _, c := range pa.Communities {
		ra.Communities = append(ra.Communities, (uint32(c.High)<<16)|uint32(c.Low))
	}

	for _, lc := range pa.LargeCommunities {
		ra.LargeCommunities = append(ra.LargeCommunities, routing_table.LargeCommunity{
			GlobalAdmin: lc.Admin,
			LocalData1:  lc.High,
			LocalData2:  lc.Low,
		})
	}

	return ra
}

func (p *peer) processRibUpdates() {
	p.mutex.RLock()
	prefixes := p.prefixes
	p.mutex.RUnlock()

	if prefixes == nil {
		return
	}

	p.mutex.Lock()
	p.withdraws += uint64(len(prefixes.V4Withdraws) + len(prefixes.V6Withdraws))
	p.updates += uint64(len(prefixes.V4prefixes) + len(prefixes.V6prefixes))
	p.mutex.Unlock()

	// Process withdrawals
	if len(prefixes.V4Withdraws) > 0 && p.v4rib != nil {
		var v4w []routing_table.PrefixWithID
		for _, w := range prefixes.V4Withdraws {
			if ip, ok := netip.AddrFromSlice(w.Prefix); ok {
				prefix := netip.PrefixFrom(ip, int(w.Mask))
				v4w = append(v4w, routing_table.PrefixWithID{Prefix: prefix, PathID: w.ID})
			}
		}
		removedV4 := p.v4rib.DeleteBatch(v4w)
		if len(removedV4) > 0 {
			p.server.removeGlobalV4(removedV4)
		}
	}

	if len(prefixes.V6Withdraws) > 0 && p.v6rib != nil {
		var v6w []routing_table.PrefixWithID
		for _, w := range prefixes.V6Withdraws {
			if ip, ok := netip.AddrFromSlice(w.Prefix); ok {
				prefix := netip.PrefixFrom(ip, int(w.Mask))
				v6w = append(v6w, routing_table.PrefixWithID{Prefix: prefix, PathID: w.ID})
			}
		}
		removedV6 := p.v6rib.DeleteBatch(v6w)
		if len(removedV6) > 0 {
			p.server.removeGlobalV6(removedV6)
		}
	}

	// Process announcements
	if prefixes.Attr != nil && (len(prefixes.V4prefixes) > 0 || len(prefixes.V6prefixes) > 0) {
		ra := mapAttributes(prefixes.Attr)

		if len(prefixes.V4prefixes) > 0 && p.v4rib != nil {
			var v4a []routing_table.Route
			for _, pfx := range prefixes.V4prefixes {
				if ip, ok := netip.AddrFromSlice(pfx.Prefix); ok {
					prefix := netip.PrefixFrom(ip, int(pfx.Mask))
					v4a = append(v4a, routing_table.Route{
						Prefix:     prefix,
						Attributes: ra,
						PathID:     pfx.ID,
					})
				}
			}
			newV4 := p.v4rib.InsertBatch(v4a)
			if len(newV4) > 0 {
				p.server.addGlobalV4(newV4)
			}
		}

		if len(prefixes.V6prefixes) > 0 && p.v6rib != nil {
			var v6a []routing_table.Route
			for _, pfx := range prefixes.V6prefixes {
				if ip, ok := netip.AddrFromSlice(pfx.Prefix); ok {
					prefix := netip.PrefixFrom(ip, int(pfx.Mask))
					v6a = append(v6a, routing_table.Route{
						Prefix:     prefix,
						Attributes: ra,
						PathID:     pfx.ID,
					})
				}
			}
			newV6 := p.v6rib.InsertBatch(v6a)
			if len(newV6) > 0 {
				p.server.addGlobalV6(newV6)
			}
		}
	}

	if prefixes.V4EoR || prefixes.V6EoR {
		v4c, v6c := 0, 0
		if p.v4rib != nil {
			v4c = p.v4rib.Count()
		}
		if p.v6rib != nil {
			v6c = p.v6rib.Count()
		}
		log.Printf("Peer %s sent EoR. Routes: %d IPv4, %d IPv6",
			p.ip, v4c, v6c)

		// Notify GR manager that EoR has been received
		currentStatus := PeerStatus(p.status.Load())
		if currentStatus == StatusWaitingForEOR {
			if prefixes.V4EoR {
				go func() {
					if err := p.server.grManager.ReceiveEoR(context.Background(), p.ip, Family{AFI: 1, SAFI: 1}); err != nil {
						log.Printf("GR V4 EoR cleanup error for %s: %v", p.ip, err)
					}
				}()
			}
			if prefixes.V6EoR {
				go func() {
					if err := p.server.grManager.ReceiveEoR(context.Background(), p.ip, Family{AFI: 2, SAFI: 1}); err != nil {
						log.Printf("GR V6 EoR cleanup error for %s: %v", p.ip, err)
					}
				}()
			}
		}

		p.memCleanupOnce.Do(func() {
			go func() {
				time.Sleep(15 * time.Second)
				log.Printf("Running FreeOSMemory after EoR convergence for peer %s", p.ip)
				debug.FreeOSMemory()
				log.Printf("FreeOSMemory complete for peer %s", p.ip)
			}()
		})
	}
}
