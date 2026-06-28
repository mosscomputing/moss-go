package sidecar

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// HeartbeatResponse is the body returned by POST /v1/agents/{id}/heartbeat.
type HeartbeatResponse struct {
	LeaseExpiresAt   string `json:"lease_expires_at"`
	RevocationEpoch  int64  `json:"revocation_epoch"`
	Revoked          bool   `json:"revoked"`
	ServerTime       string `json:"server_time"`
	LeaseTTLSeconds  int    `json:"lease_ttl_seconds,omitempty"`
}

// PostHeartbeat sends a heartbeat for the agent and returns the server
// response. A revoked agent receives revoked:true (push fast path) without
// lease renewal. The agent must already be registered in MOSS.
func PostHeartbeat(cfg Config, agentID string) (*HeartbeatResponse, error) {
	if agentID == "" {
		return nil, fmt.Errorf("sidecar: heartbeat requires agent id")
	}
	url := strings.TrimRight(cfg.APIURL, "/") + "/v1/agents/" + agentID + "/heartbeat"
	body := map[string]any{
		"sdk_version":   "moss-go-sidecar",
		"runtime_info":  map[string]any{"sidecar": true},
		"lease_ttl":     20,
	}
	bodyBytes, _ := json.Marshal(body)
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(bodyBytes))
	if err != nil {
		return nil, fmt.Errorf("sidecar: build heartbeat request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+cfg.APIKey)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")

	client := &http.Client{Timeout: 10 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sidecar: heartbeat request: %w", err)
	}
	defer resp.Body.Close()
	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("sidecar: read heartbeat body: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("sidecar: heartbeat HTTP %d: %s", resp.StatusCode, truncate(string(respBody), 200))
	}
	var hb HeartbeatResponse
	if err := json.Unmarshal(respBody, &hb); err != nil {
		return nil, fmt.Errorf("sidecar: parse heartbeat response: %w", err)
	}
	return &hb, nil
}
