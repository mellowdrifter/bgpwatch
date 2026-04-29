package procstats

import (
	"fmt"
	"os"
	"strings"
	"sync/atomic"
	"time"
)

type MemStats struct {
	PSSBytes int64
	RSSBytes int64
	Updated  int64 // unix nano
}

type Sampler struct {
	stats atomic.Value // holds MemStats
}

func NewSampler(interval time.Duration) *Sampler {
	s := &Sampler{}
	s.stats.Store(MemStats{})

	go s.loop(interval)
	return s
}

func (s *Sampler) loop(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		sample := readSmapsRollup()
		if sample.PSSBytes > 0 {
			sample.Updated = time.Now().UnixNano()
			s.stats.Store(sample)
		}
		<-ticker.C
	}
}

func (s *Sampler) Get() MemStats {
	return s.stats.Load().(MemStats)
}

func readSmapsRollup() MemStats {
	data, err := os.ReadFile("/proc/self/smaps_rollup")
	if err != nil {
		return MemStats{}
	}

	var pssKB, rssKB int64

	for _, line := range strings.Split(string(data), "\n") {
		if strings.HasPrefix(line, "Pss:") {
			fmt.Sscanf(line, "Pss: %d kB", &pssKB)
		}
		if strings.HasPrefix(line, "Rss:") {
			fmt.Sscanf(line, "Rss: %d kB", &rssKB)
		}
	}

	return MemStats{
		PSSBytes: pssKB * 1024,
		RSSBytes: rssKB * 1024,
	}
}
