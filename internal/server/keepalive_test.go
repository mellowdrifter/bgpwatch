package server

import (
	"bytes"
	"io"
	"net"
	"testing"
	"time"

	"github.com/mellowdrifter/bgpwatch/internal/bgp"
)

// sendKeepalives must emit KEEPALIVEs on its own every holdtime/3, without waiting
// for the remote to send one first.
func TestSendKeepalivesPeriodic(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	p := &peer{conn: local, holdtime: 3} // 3s hold time -> 1s interval
	done := make(chan struct{})
	defer close(done)
	go p.sendKeepalives(done)

	want := bgp.CreateKeepAlive()
	for i := 0; i < 2; i++ {
		remote.SetReadDeadline(time.Now().Add(2 * time.Second))
		got := make([]byte, len(want))
		if _, err := io.ReadFull(remote, got); err != nil {
			t.Fatalf("keepalive %d not received: %v", i+1, err)
		}
		if !bytes.Equal(got, want) {
			t.Fatalf("keepalive %d = %x, want %x", i+1, got, want)
		}
	}
}

// A hold time of 0 means keepalives are not used (RFC 4271), so none may be sent.
func TestSendKeepalivesZeroHoldtime(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	p := &peer{conn: local, holdtime: 0}
	finished := make(chan struct{})
	go func() {
		p.sendKeepalives(make(chan struct{}))
		close(finished)
	}()

	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("sendKeepalives should return immediately for holdtime 0")
	}
}

// The sender must stop when the peer worker exits (done closed).
func TestSendKeepalivesStopsOnDone(t *testing.T) {
	local, remote := net.Pipe()
	defer local.Close()
	defer remote.Close()

	p := &peer{conn: local, holdtime: 3}
	done := make(chan struct{})
	finished := make(chan struct{})
	go func() {
		p.sendKeepalives(done)
		close(finished)
	}()

	close(done)
	select {
	case <-finished:
	case <-time.After(time.Second):
		t.Fatal("sendKeepalives did not stop after done was closed")
	}
}
