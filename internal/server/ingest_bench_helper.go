package server

import (
	"bytes"
	"encoding/binary"
	"net"
	"runtime"
	"time"

	"github.com/mellowdrifter/bgpwatch/internal/bgp"
)

// IngestBenchmark runs a full-table ingestion benchmark.
// It returns stats about the run.
type BenchStats struct {
	Duration         time.Duration
	GCCycles         uint32
	TotalAlloc       uint64
	HeapObjs         uint64
	SteadyStateHeap  uint64
}

func RunIngestBenchmark(prefixCount int, useAddPath bool) (BenchStats, error) {
	// 1. Setup mock server and peer
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
	if useAddPath {
		p.param.AddPath = []bgp.AddPathCapability{
			{AFI: 1, SAFI: 1, SendReceive: 3},
		}
	}

	// 2. Start peer worker in background
	done := make(chan bool)
	go func() {
		p.peerWorker()
		done <- true
	}()

	// 3. Prepare data
	// Pack 100 prefixes per message to be more realistic
	packCount := 100
	updateMsg := generateMockUpdate(useAddPath, packCount)
	
	// 4. Record baseline stats
	runtime.GC()
	var m1, m2 runtime.MemStats
	runtime.ReadMemStats(&m1)
	start := time.Now()

	// 5. Push messages
	msgCount := prefixCount / packCount
	for i := 0; i < msgCount; i++ {
		_, err := c2.Write(updateMsg)
		if err != nil {
			return BenchStats{}, err
		}
	}

	// Send EoR
	eor := generateEoR()
	c2.Write(eor)

	// Close connection to stop peerWorker
	c2.Close()
	<-done

	// 6. Record end stats
	duration := time.Since(start)
	runtime.ReadMemStats(&m2)

	// 7. Measure Steady State (wait for internal cleanup if any)
	time.Sleep(1 * time.Second)
	runtime.GC()
	var m3 runtime.MemStats
	runtime.ReadMemStats(&m3)

	return BenchStats{
		Duration:        duration,
		GCCycles:        m2.NumGC - m1.NumGC,
		TotalAlloc:      m2.TotalAlloc - m1.TotalAlloc,
		HeapObjs:        m2.HeapObjects,
		SteadyStateHeap: m3.HeapAlloc,
	}, nil
}

func generateMockUpdate(addPath bool, packCount int) []byte {
	// Marker
	marker := make([]byte, 16)
	for i := range marker {
		marker[i] = 0xff
	}

	// NLRI: 1.2.3.0/24 (repeated with changing last octet)
	var nlri []byte
	for i := 0; i < packCount; i++ {
		if addPath {
			// PathID (4 bytes) + Mask (1) + Prefix
			nlri = append(nlri, []byte{0, 0, 0, 1, 24, 1, 2, byte(i % 256)}...)
		} else {
			nlri = append(nlri, []byte{24, 1, 2, byte(i % 256)}...)
		}
	}

	attr := []byte{
		0x40, 0x01, 0x01, 0x00, // Origin: IGP
		0x40, 0x03, 0x04, 10, 0, 0, 1, // Next-Hop: 10.0.0.1
	}

	msgLen := uint16(16 + 2 + 1 + 2 + 2 + len(attr) + len(nlri))
	buf := new(bytes.Buffer)
	buf.Write(marker)
	binary.Write(buf, binary.BigEndian, msgLen)
	buf.WriteByte(uint8(bgp.Update))
	binary.Write(buf, binary.BigEndian, uint16(0)) // No withdrawals
	binary.Write(buf, binary.BigEndian, uint16(len(attr)))
	buf.Write(attr)
	buf.Write(nlri)

	return buf.Bytes()
}

func generateEoR() []byte {
	marker := make([]byte, 16)
	for i := range marker {
		marker[i] = 0xff
	}
	// EoR is an empty Update
	msgLen := uint16(16 + 2 + 1 + 2 + 2)
	buf := new(bytes.Buffer)
	buf.Write(marker)
	binary.Write(buf, binary.BigEndian, msgLen)
	buf.WriteByte(uint8(bgp.Update))
	binary.Write(buf, binary.BigEndian, uint16(0))
	binary.Write(buf, binary.BigEndian, uint16(0))
	return buf.Bytes()
}
