package server

import (
	"encoding/json"
	"fmt"
	"os"
)

// PeerConfig holds the configuration for a single peer
type PeerConfig struct {
	IP       string `json:"ip"`
	Password string `json:"password,omitempty"`
}

// ConfigFile represents the JSON configuration file
type ConfigFile struct {
	Peers []PeerConfig `json:"peers"`
}

// LoadConfigFile reads and parses the JSON configuration file.
// It returns a map of IP address strings to PeerConfig for O(1) lookups.
func LoadConfigFile(filename string) (map[string]PeerConfig, error) {
	if filename == "" {
		return nil, fmt.Errorf("config filename is empty")
	}

	b, err := os.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %v", err)
	}

	var cf ConfigFile
	if err := json.Unmarshal(b, &cf); err != nil {
		return nil, fmt.Errorf("failed to parse JSON config: %v", err)
	}

	peersMap := make(map[string]PeerConfig)
	for _, p := range cf.Peers {
		if p.IP == "" {
			return nil, fmt.Errorf("peer entry missing IP address")
		}
		peersMap[p.IP] = p
	}

	return peersMap, nil
}
