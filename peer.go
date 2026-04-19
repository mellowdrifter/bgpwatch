package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

var (
	bgpMarker = []byte{
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
		0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
	}
)

type peer struct {
	server        *bgpWatchServer
	asn           uint16
	holdtime      uint16
	ip            string
	conn          net.Conn
	eor           bool
	weor          bool
	mutex         sync.RWMutex
	param         parameters
	rid           bgpid
	keepalives    uint64
	lastKeepalive time.Time
	updates       uint64
	withdraws     uint64
	startTime     time.Time
	in            *bytes.Reader
	out           *bytes.Buffer
	prefixes      *prefixAttributes
}

func (p *peer) peerWorker() {
	defer p.server.remove(p)
	for {

		// Grab incoming BGP message and place into a reader.
		msg, err := getMessage(p.conn)
		if err != nil {
			log.Printf("Bad BGP message: %v\n", err)
			p.conn.Close()
			return

		}
		// Create a reader from that byte slice and insert into the peer struct
		p.in = bytes.NewReader(msg)

		// Grab the header
		header, err := p.getType()
		if err != nil {
			log.Printf("Unable to decode header: %v\n", err)
			p.conn.Close()
			return
		}

		switch header {
		case open:
			if err := p.HandleOpen(); err != nil {
				log.Printf("Error handling Open: %v\n", err)
				p.conn.Close()
				return
			}
			p.createOpen()
			// TODO: Following should go outside of the switch statement once the rest are done
			p.encodeOutgoing()

		case keepalive:
			if err := p.HandleKeepalive(); err != nil {
				log.Printf("Error handling Keepalive: %v\n", err)
				p.conn.Close()
				return
			}
			p.createKeepAlive()
			p.encodeOutgoing()

		case update:
			if err := p.handleUpdate(); err != nil {
				log.Printf("Error handling Update: %v\n", err)
				p.conn.Close()
				return
			}

			// output and dump that update
			p.logUpdate()

		case notification:
			if err := p.handleNotification(); err != nil {
				log.Printf("Error handling Notification: %v\n", err)
				p.conn.Close()
			}
			return

		default:
			log.Printf("Unknown BGP message inbound: %+v\n", p.in)
		}
	}
}

// TODO: Maximum size could be more than 4k if implementing that RFC that allows 65K
// TODO: TEST
func getMessage(c net.Conn) ([]byte, error) {

	// Grab the first 18 bytes. 16 for the marker and 2 for the size.
	header := make([]byte, 18)
	_, err := io.ReadFull(c, header)
	if err != nil {
		return nil, err
	}

	// Check for BGP marker
	if bytes.Compare(header[:16], bgpMarker) != 0 {
		return nil, fmt.Errorf("Packet is not a BGP packet as does not have the marker present")
	}

	msgLen := getMessageLength(header[16:])
	if msgLen < minMessage || msgLen > maxMessage {
		return nil, fmt.Errorf("invalid BGP message length: %d", msgLen)
	}

	// len will be the remainder of the packet, minus the 18 bytes already taken above.
	remLen := msgLen - 18
	buffer := make([]byte, remLen)

	// Read in the rest of the packet and return.
	_, err = io.ReadFull(c, buffer)
	if err != nil {
		return nil, err
	}
	return buffer, nil
}

// BGP packet length is two fields long
// TODO: TEST
func getMessageLength(b []byte) int {
	return int(b[0])*256 + int(b[1])
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
	log.Printf("received keepalive #%d\n", p.keepalives)
	return nil
}

func (p *peer) HandleOpen() error {
	log.Println("Received Open Message")
	var o msgOpen
	if err := binary.Read(p.in, binary.BigEndian, &o); err != nil {
		return err
	}

	// Read parameters into new buffer
	pbuffer := make([]byte, int(o.ParamLen))
	if _, err := io.ReadFull(p.in, pbuffer); err != nil {
		return err
	}

	params, err := decodeOptionalParameters(&pbuffer)
	if err != nil {
		return err
	}

	p.mutex.Lock()
	defer p.mutex.Unlock()

	// Grab the ASN and Hold Time.
	p.asn = o.ASN
	p.holdtime = o.HoldTime
	p.param = params
	return nil
}

func (p *peer) handleNotification() error {
	var n msgNotification
	if err := binary.Read(p.in, binary.BigEndian, &n); err != nil {
		return err
	}

	log.Printf("Notification received: code is %d with subcode %d\n", n.Code, n.Subcode)
	log.Println("Closing session")
	// TODO: This closes the session, but it does not yet remove the session
	p.conn.Close()
	return nil
}

// Handle update messages. IPv6 updates are encoded in attributes unlike IPv4.
func (p *peer) handleUpdate() error {
	var pa prefixAttributes

	var withdraw uint16
	if err := binary.Read(p.in, binary.BigEndian, &withdraw); err != nil {
		return err
	}

	// IPv4 withdraws are done here
	// TODO: IPv4 Path ID withdraws?
	if withdraw != 0 {
		wbuf := make([]byte, withdraw)
		if _, err := io.ReadFull(p.in, wbuf); err != nil {
			return err
		}
		wd, err := decodeIPv4Withdraws(wbuf)
		if err != nil {
			return err
		}
		pa.v4Withdraws = wd.v4Withdraws
	}

	var attrLength twoByteLength
	if err := binary.Read(p.in, binary.BigEndian, &attrLength); err != nil {
		return err
	}

	// Zero withdraws and zero attributes means IPv4 End-of-RIB
	if withdraw == 0 && attrLength.toUint16() == 0 {
		p.mutex.Lock()
		p.eor = true
		pa.v4EoR = true
		p.prefixes = &pa
		p.mutex.Unlock()
		return nil
	}

	if attrLength.toUint16() == 0 {
		p.mutex.Lock()
		p.prefixes = &pa
		p.mutex.Unlock()
		return nil
	}

	// Drain all path attributes into a new buffer to decode.
	abuf := make([]byte, attrLength.toUint16())
	if _, err := io.ReadFull(p.in, abuf); err != nil {
		return err
	}

	// decode attributes
	attr, err := decodePathAttributes(abuf, p.param.AddPath)
	if err != nil {
		return err
	}
	pa.attr = attr

	// Any remaining bytes are IPv4 NLRI
	if p.in.Len() > 0 {
		v4prefixes, err := decodeIPv4NLRI(p.in, p.param.AddPath)
		if err != nil {
			return err
		}
		pa.v4prefixes = v4prefixes
	}

	// Copy certain attributes over to upper struct
	if pa.attr != nil {
		pa.v6prefixes = pa.attr.ipv6NLRI
		pa.v6NextHops = pa.attr.nextHopsv6
		pa.v6EoR = pa.attr.v6EoR
	}

	p.mutex.Lock()
	p.prefixes = &pa
	p.mutex.Unlock()
	return nil
}

//TODO: Not showing IPv4 Next-Hop
func (p *peer) logUpdate() {
	// If waiting for EoR and not yet received, output nothing
	if p.weor && !p.eor {
		p.mutex.Lock()
		p.prefixes = nil
		p.mutex.Unlock()
		return
	}

	log.Println("----------------------")
	p.mutex.RLock()
	if len(p.prefixes.v4prefixes) != 0 {
		if len(p.prefixes.v4prefixes) == 1 {
			log.Printf("Received the following IPv4 prefix:")
		} else {
			log.Printf("Received the following IPv4 prefixes:")

		}
		for _, prefix := range p.prefixes.v4prefixes {
			log.Printf("%v/%d\n", prefix.Prefix, prefix.Mask)
		}
		// TODO: This only checks a single path for it's ID
		// But each route could have this ID set, and it could be unique.
		if p.prefixes.v4prefixes[0].ID != 0 {
			log.Printf("With Path ID: %d\n", p.prefixes.v4prefixes[0].ID)
		}
	}

	if len(p.prefixes.v6prefixes) != 0 {
		if len(p.prefixes.v6prefixes) == 1 {
			log.Printf("Received the following IPv6 prefix:")
		} else {
			log.Printf("Received the following IPv6 prefixes:")
		}
		for _, prefix := range p.prefixes.v6prefixes {
			log.Printf("%v/%d\n", prefix.Prefix, prefix.Mask)
		}
		// TODO: This only checks a single path for it's ID
		// But each route could have this ID set, and it could be unique.
		if p.prefixes.v6prefixes[0].ID != 0 {
			log.Printf("With Path ID: %d\n", p.prefixes.v6prefixes[0].ID)
		}
		log.Printf("With the following next-hops:")
		for _, nh := range p.prefixes.v6NextHops {
			log.Printf("%v\n", nh)
		}
	}

	// TODO: Do a better check here. Attributes not nil if IPv6 EoR, or routes withdrawn.
	if p.prefixes.attr != nil {
		log.Printf("Origin: %s\n", p.prefixes.attr.origin.string())
		if len(p.prefixes.attr.aspath) != 0 {
			path := formatASPath(&p.prefixes.attr.aspath)
			log.Printf("AS-path: %s\n", path)
		}
		if p.prefixes.attr.localPref != 0 {
			log.Printf("Local Preference: %d\n", p.prefixes.attr.localPref)
		}
		if p.prefixes.attr.originator != "" {
			log.Printf("Originator ID: %s\n", p.prefixes.attr.originator)
		}
		if len(p.prefixes.attr.clusterList) > 0 {
			list := formatClusterList(&p.prefixes.attr.clusterList)
			log.Printf("Cluster List: %v\n", list)
		}
		if p.prefixes.attr.atomic {
			log.Printf("Has the atomic aggregates set")
		}
		if p.prefixes.attr.agAS != 0 {
			log.Printf("AS aggregate ASN as %v\n", p.prefixes.attr.agAS)
		}
		if len(p.prefixes.attr.communities) > 0 {
			comm := formatCommunities(&p.prefixes.attr.communities)
			log.Printf("Communities: %s\n", comm)
		}
		if len(p.prefixes.attr.largeCommunities) > 0 {
			comm := formatLargeCommunities(&p.prefixes.attr.largeCommunities)
			log.Printf("Large Communities: %s\n", comm)
		}
	}

	if len(p.prefixes.v4Withdraws) != 0 {
		if len(p.prefixes.v4Withdraws) == 1 {
			log.Printf("Withdrawn the following IPv4 prefix:")
		} else {
			log.Printf("Withdrawn the following IPv4 prefixes:")

		}
		for _, prefix := range p.prefixes.v4Withdraws {
			log.Printf("%v/%d\n", prefix.Prefix, prefix.Mask)
		}
	}

	if len(p.prefixes.v6Withdraws) != 0 {
		if len(p.prefixes.v6Withdraws) == 1 {
			log.Printf("Withdrawn the following IPv6 prefix:")
		} else {
			log.Printf("Withdrawn the following IPv6 prefixes:")
		}
		for _, prefix := range p.prefixes.v6Withdraws {
			log.Printf("%v/%d\n", prefix.Prefix, prefix.Mask)
		}
	}

	if p.prefixes.v4EoR {
		log.Printf("IPv4 End-of-Rib received")
		p.eor = true
	}
	if p.prefixes.v6EoR {
		log.Printf("IPv6 End-of-Rib received")
		p.eor = true
	}

	p.mutex.RUnlock()

	// Empty out the prefixes field
	p.mutex.Lock()
	p.prefixes = nil
	p.mutex.Unlock()
}
