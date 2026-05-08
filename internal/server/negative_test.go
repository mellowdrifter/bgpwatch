package server

import (
	"bytes"
	"encoding/binary"
	"net"
	"testing"
	"time"

	"github.com/mellowdrifter/bgpwatch/internal/bgp"
)

func TestOversizedMessageRejection(t *testing.T) {
	rid, _ := GetRid("1.1.1.1")
	conf := Config{
		Rid:   rid,
		Asn:   64512,
		Quiet: true,
	}
	srv := New(conf)
	
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()

	p := &peer{
		server: srv,
		conn:   c1,
		ip:     "127.0.0.1",
		quiet:  true,
	}
	// ExtendedMessage is NOT enabled in p.param

	// Create a 4097 byte message
	marker := make([]byte, 16)
	for i := range marker {
		marker[i] = 0xff
	}
	msgLen := uint16(4097)
	buf := new(bytes.Buffer)
	buf.Write(marker)
	binary.Write(buf, binary.BigEndian, msgLen)
	buf.WriteByte(uint8(bgp.Keepalive))
	// Fill the rest
	buf.Write(make([]byte, 4097-19))

	go func() {
		time.Sleep(100 * time.Millisecond)
		c2.Write(buf.Bytes())
	}()

	// The peerWorker should error out and close the connection
	done := make(chan bool)
	go func() {
		p.peerWorker()
		done <- true
	}()

	select {
	case <-done:
		// Success: peerWorker exited
	case <-time.After(1 * time.Second):
		t.Fatal("peerWorker did not exit after receiving oversized message")
	}
}
