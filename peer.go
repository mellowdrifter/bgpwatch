package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"log"
	"net"
	"sync"
	"time"
)

type peer struct {
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

		// marker should be checked and removed via the getMessage function
		var m marker
		binary.Read(p.in, binary.BigEndian, &m)

		// Grab the header
		header, err := p.getHeader()
		if err != nil {
			log.Printf("Unable to decode header: %v\n", err)
			return
		}

		switch header.Type {
		case open:
			p.HandleOpen()
			p.createOpen()
			// TODO: Following should go outside of the switch statement once the rest are done
			p.encodeOutgoing()

		case keepalive:
			p.HandleKeepalive()
			p.createKeepAlive()
			p.encodeOutgoing()

		case update:
			p.handleUpdate()

			// output and dump that update
			p.logUpdate()

		case notification:
			p.handleNotification()
			return

		default:
			log.Printf("Unknown BGP message inbound: %#v\n", p.in)
			//io.CopyN(ioutil.Discard, p.in, int64(header.Length))
		}
	}
}

func (p *peer) getHeader() (header, error) {
	var h header
	binary.Read(p.in, binary.BigEndian, &h)

	return h, nil
}

func (p *peer) HandleKeepalive() {
	p.mutex.Lock()
	p.keepalives++
	p.lastKeepalive = time.Now()
	p.mutex.Unlock()
	log.Printf("received keepalive #%d\n", p.keepalives)
}

func (p *peer) HandleOpen() {
	defer p.mutex.Unlock()
	log.Println("Received Open Message")
	var o msgOpen
	binary.Read(p.in, binary.BigEndian, &o)

	// Read parameters into new buffer
	pbuffer := make([]byte, int(o.ParamLen))
	// TODO: errors
	io.ReadFull(p.in, pbuffer)

	// Grab the ASN and Hold Time.
	p.asn = o.ASN
	p.holdtime = o.HoldTime

	p.mutex.Lock()
	p.param = decodeOptionalParameters(&pbuffer)

}

func (p *peer) handleNotification() {
	var n msgNotification
	binary.Read(p.in, binary.BigEndian, &n)

	log.Printf("Notification received: code is %d with subcode %d\n", n.Code, n.Subcode)
	log.Println("Closing session")
	// TODO: This closes the session, but it does not yet remove the session
	p.conn.Close()

}

// Handle update messages. IPv6 updates are encoded in attributes unlike IPv4.
func (p *peer) handleUpdate() {
	var pa prefixAttributes
	var u msgUpdate
	binary.Read(p.in, binary.BigEndian, &u)

	// If IPv4 EoR, exit early
	if u.Withdraws == 0 && u.AttrLength.toUint16() == 0 {
		p.mutex.Lock()
		p.eor = true
		pa.v4EoR = true
		p.prefixes = &pa
		p.mutex.Unlock()
		return
	}

	if u.AttrLength.toUint16() == 0 {
		return
	}

	// IPv4 withdraws are done here
	if u.Withdraws != 0 {
		wbuf := make([]byte, u.Withdraws)
		io.ReadFull(p.in, wbuf)
		p.mutex.Lock()
		p.prefixes = decodeIPv4Withdraws(wbuf)
		p.mutex.Unlock()
		return
	}

	// Drain all path attributes into a new buffer to decode.
	abuf := make([]byte, u.AttrLength.toUint16())
	io.ReadFull(p.in, abuf)

	// decode attributes
	pa.attr = decodePathAttributes(abuf)

	// IPv6 updates are done via attributes. Only pass the remainder of the buffer to decodeIPv4NLRI if
	// there are no IPv6 updates in the attributes.
	if len(pa.attr.ipv6NLRI) == 0 && !pa.attr.v6EoR {
		// dump the rest of the update message into a buffer to use for NLRI
		// It is possible to work this out as well... needed for a copy.
		// for now just read the last of the in buffer :(
		pa.v4prefixes = decodeIPv4NLRI(p.in)
		// TODO: What about withdraws???
	} else {
		// Copy certain attributes over to upper struct
		pa.v6prefixes = pa.attr.ipv6NLRI
		pa.v6NextHops = pa.attr.nextHopsv6
		pa.v6EoR = pa.attr.v6EoR
	}

	p.mutex.Lock()
	p.prefixes = &pa
	p.mutex.Unlock()
}

func (p *peer) logUpdate() {
	// If waiting for EoR and not yet received, output nothing
	if p.weor && !p.eor {
		p.mutex.Lock()
		p.prefixes = nil
		p.mutex.Unlock()
		return
	}

	p.mutex.RLock()
	log.Println("**********START**********")
	if len(p.prefixes.v4prefixes) != 0 {
		log.Printf("Received the following IPv4 prefixes:")
		for _, prefix := range p.prefixes.v4prefixes {
			log.Printf("%v/%d\n", prefix.Prefix, prefix.Mask)
		}
	}

	if len(p.prefixes.v6prefixes) != 0 {
		log.Printf("Received the following IPv6 prefixes:")
		for _, prefix := range p.prefixes.v6prefixes {
			log.Printf("%v/%d\n", prefix.Prefix, prefix.Mask)
		}
		log.Printf("With the following next-hops:")
		for _, nh := range p.prefixes.v6NextHops {
			log.Printf("%v\n", nh)
		}
	}

	if p.prefixes.attr != nil {
		log.Printf("Origin is %d\n", p.prefixes.attr.origin)
		log.Printf("ASPATH is %v\n", p.prefixes.attr.aspath)
		if p.prefixes.attr.atomic {
			log.Printf("Has the atomic aggregates set")
		}
		if p.prefixes.attr.agAS != 0 {
			log.Printf("As aggregate ASN as %v\n", p.prefixes.attr.agAS)
		}
		if len(p.prefixes.attr.communities) > 0 {
			log.Printf("Has the following communities: %v\n", p.prefixes.attr.communities)
		}
		if len(p.prefixes.attr.largeCommunities) > 0 {
			log.Printf("Has the following large communities: %v\n", p.prefixes.attr.largeCommunities)
		}
	}

	// TODO: prefixes withdrawn

	if p.prefixes.v4EoR {
		log.Printf("IPv4 End-of-Rib received")
		p.eor = true
	}
	if p.prefixes.v6EoR {
		log.Printf("IPv6 End-of-Rib received")
		p.eor = true
	}

	p.mutex.RUnlock()
	log.Println("***********END***********")

	// Empty out the prefixes field
	p.mutex.Lock()
	p.prefixes = nil
	p.mutex.Unlock()
}
