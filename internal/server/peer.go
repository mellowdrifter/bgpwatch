package server

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"time"

	"github.com/mellowdrifter/bgpwatch/internal/bgp"
	"github.com/mellowdrifter/routing_table"
)

var (
	bgpMarker = []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}
)

type peer struct {
	server        *Server
	peerAsn       uint32
	isIBGP        bool
	holdtime      uint16
	ip            string
	conn          net.Conn
	eor           bool
	weor          bool
	quiet         bool
	mutex         sync.RWMutex
	param         bgp.Parameters
	rid           bgp.BGPID
	keepalives    uint64
	lastKeepalive time.Time
	updates       uint64
	withdraws     uint64
	startTime       time.Time
	establishedTime time.Time
	in            *bytes.Reader
	out           *bytes.Buffer
	prefixes      *bgp.PrefixAttributes
	rib           routing_table.Rib
}

func (p *peer) peerWorker() {
	defer p.server.remove(p)
	for {
		msg, err := getMessage(p.conn)
		if err != nil {
			log.Printf("Bad BGP message: %v\n", err)
			p.conn.Close()
			return
		}
		p.in = bytes.NewReader(msg)

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
			log.Printf("Unknown BGP message inbound: %d\n", header)
		}
	}
}

func getMessage(c net.Conn) ([]byte, error) {
	header := make([]byte, 18)
	if _, err := io.ReadFull(c, header); err != nil {
		return nil, err
	}

	if !bytes.Equal(header[:16], bgpMarker) {
		return nil, fmt.Errorf("packet is not a BGP packet")
	}

	msgLen := int(binary.BigEndian.Uint16(header[16:]))
	if msgLen < bgp.MinMessage || msgLen > bgp.MaxMessage {
		return nil, fmt.Errorf("invalid BGP message length: %d", msgLen)
	}

	remLen := msgLen - 18
	buffer := make([]byte, remLen)
	if _, err := io.ReadFull(c, buffer); err != nil {
		return nil, err
	}
	return buffer, nil
}

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
	log.Printf("received keepalive #%d from %s\n", p.keepalives, p.ip)
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
		p.eor = true
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
	p.prefixes = &pa
	p.mutex.Unlock()

	p.processRibUpdates()
	return nil
}

func (p *peer) logUpdate() {
	if p.weor && !p.eor {
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
		p.eor = true
	}
	if p.prefixes.V6EoR {
		log.Printf("IPv6 End-of-Rib received from %s", p.ip)
		p.eor = true
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
	if len(prefixes.V4Withdraws) > 0 {
		var v4w []routing_table.PrefixWithID
		for _, w := range prefixes.V4Withdraws {
			if ip, ok := netip.AddrFromSlice(w.Prefix); ok {
				prefix := netip.PrefixFrom(ip, int(w.Mask))
				v4w = append(v4w, routing_table.PrefixWithID{Prefix: prefix, PathID: w.ID})
			}
		}
		removedV4 := p.rib.DeleteIPv4Batch(v4w)
		if len(removedV4) > 0 {
			p.server.removeGlobalV4(removedV4)
		}
	}

	if len(prefixes.V6Withdraws) > 0 {
		var v6w []routing_table.PrefixWithID
		for _, w := range prefixes.V6Withdraws {
			if ip, ok := netip.AddrFromSlice(w.Prefix); ok {
				prefix := netip.PrefixFrom(ip, int(w.Mask))
				v6w = append(v6w, routing_table.PrefixWithID{Prefix: prefix, PathID: w.ID})
			}
		}
		removedV6 := p.rib.DeleteIPv6Batch(v6w)
		if len(removedV6) > 0 {
			p.server.removeGlobalV6(removedV6)
		}
	}

	// Process announcements
	if prefixes.Attr != nil && (len(prefixes.V4prefixes) > 0 || len(prefixes.V6prefixes) > 0) {
		ra := mapAttributes(prefixes.Attr)

		if len(prefixes.V4prefixes) > 0 {
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
			newV4 := p.rib.InsertIPv4Batch(v4a)
			if len(newV4) > 0 {
				p.server.addGlobalV4(newV4)
			}
		}

		if len(prefixes.V6prefixes) > 0 {
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
			newV6 := p.rib.InsertIPv6Batch(v6a)
			if len(newV6) > 0 {
				p.server.addGlobalV6(newV6)
			}
		}
	}

	if prefixes.V4EoR || prefixes.V6EoR {
		log.Printf("Peer %s sent EoR. Routes: %d IPv4, %d IPv6", 
			p.ip, p.rib.V4Count(), p.rib.V6Count())
		
		go func() {
			time.Sleep(5 * time.Second)
			runtime.GC()
			log.Printf("Garbage collector forced after EoR for peer %s", p.ip)
		}()
	}
}
