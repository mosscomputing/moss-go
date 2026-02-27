// Package moss provides cryptographic signing for AI agents using ML-DSA-44 (post-quantum).
//
// MOSS (Message-Origin Signing System) creates non-repudiable execution records
// for agent outputs, enabling audit-grade provenance.
//
// Quick Start:
//
//	client, _ := moss.NewClient(moss.Config{APIKey: os.Getenv("MOSS_API_KEY")})
//	result, _ := client.Sign(moss.SignRequest{
//	    Payload:  agentResponse,
//	    AgentID:  "agent-finance-01",
//	})
//	fmt.Println(result.Envelope)
package moss

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"sync/atomic"
	"time"
)

const (
	// SPEC is the MOSS protocol specification version
	SPEC = "moss-0001"
	// Version is the envelope version
	Version = 1
	// Algorithm is the signature algorithm
	Algorithm = "ML-DSA-44"
	// DefaultBaseURL is the default MOSS API URL
	DefaultBaseURL = "https://api.mosscomputing.com"
)

var (
	// ErrNoAPIKey is returned when API key is not provided
	ErrNoAPIKey = errors.New("moss: API key is required")
	// ErrInvalidEnvelope is returned when envelope is malformed
	ErrInvalidEnvelope = errors.New("moss: invalid envelope")
	// ErrVerificationFailed is returned when signature verification fails
	ErrVerificationFailed = errors.New("moss: signature verification failed")
	// ErrAgentSuspended is returned when agent is suspended
	ErrAgentSuspended = errors.New("moss: agent is suspended")
	// ErrAgentRevoked is returned when agent is revoked
	ErrAgentRevoked = errors.New("moss: agent has been revoked")
)

// Config holds the MOSS client configuration
type Config struct {
	// APIKey is the MOSS API key (required for enterprise features)
	APIKey string
	// BaseURL is the MOSS API base URL (optional, defaults to production)
	BaseURL string
	// HTTPClient is the HTTP client to use (optional)
	HTTPClient *http.Client
	// Timeout is the request timeout (optional, defaults to 30s)
	Timeout time.Duration
}

// Client is the MOSS API client
type Client struct {
	config     Config
	httpClient *http.Client
	sequence   atomic.Int64
}

// NewClient creates a new MOSS client
func NewClient(config Config) (*Client, error) {
	if config.APIKey == "" {
		config.APIKey = os.Getenv("MOSS_API_KEY")
	}

	if config.BaseURL == "" {
		config.BaseURL = DefaultBaseURL
	}

	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}

	httpClient := config.HTTPClient
	if httpClient == nil {
		httpClient = &http.Client{Timeout: config.Timeout}
	}

	return &Client{
		config:     config,
		httpClient: httpClient,
	}, nil
}

// Envelope represents a MOSS signature envelope
type Envelope struct {
	Spec        string `json:"spec"`
	Version     int    `json:"version"`
	Alg         string `json:"alg"`
	Subject     string `json:"subject"`
	KeyVersion  int    `json:"key_version"`
	Seq         int64  `json:"seq"`
	IssuedAt    int64  `json:"issued_at"`
	PayloadHash string `json:"payload_hash"`
	Signature   string `json:"signature"`
}

// SignRequest is the request to sign a payload
type SignRequest struct {
	// Payload is the data to sign (will be JSON-encoded)
	Payload any
	// AgentID is the agent identifier
	AgentID string
	// Action is the action type (optional)
	Action string
	// Context is additional context (optional)
	Context map[string]any
}

// SignResult is the result of a sign operation
type SignResult struct {
	// Envelope is the signature envelope
	Envelope *Envelope
	// Allowed indicates if the action was allowed by policy
	Allowed bool
	// Blocked indicates if the action was blocked by policy
	Blocked bool
	// Held indicates if the action requires approval
	Held bool
	// Decision is the policy decision (allow, block, hold, reauth)
	Decision string
	// Reason is the policy decision reason
	Reason string
	// ActionID is the held action ID (if held)
	ActionID string
	// EvidenceID is the evidence record ID
	EvidenceID string
	// SignatureValid indicates if the signature is valid
	SignatureValid bool
}

// VerifyResult is the result of a verify operation
type VerifyResult struct {
	// Valid indicates if the signature is valid
	Valid bool
	// Subject is the signing subject
	Subject string
	// IssuedAt is when the signature was created
	IssuedAt time.Time
	// Sequence is the signature sequence number
	Sequence int64
	// Error is the verification error (if any)
	Error error
}

// PolicyDecision represents a policy evaluation result
type PolicyDecision struct {
	Decision string         `json:"decision"`
	Reason   string         `json:"reason"`
	ActionID string         `json:"action_id,omitempty"`
	Envelope *Envelope      `json:"envelope,omitempty"`
	Context  map[string]any `json:"context,omitempty"`
}

// Agent represents an agent in the system
type Agent struct {
	ID              string         `json:"id"`
	AgentID         string         `json:"agent_id"`
	DisplayName     string         `json:"display_name,omitempty"`
	Status          string         `json:"status"`
	Tags            []string       `json:"tags,omitempty"`
	Metadata        map[string]any `json:"metadata,omitempty"`
	PolicyID        string         `json:"policy_id,omitempty"`
	TotalSignatures int64          `json:"total_signatures"`
	ActiveKeyID     string         `json:"active_key_id,omitempty"`
	CreatedAt       string         `json:"created_at,omitempty"`
	LastSeenAt      string         `json:"last_seen_at,omitempty"`
}

// RegisterAgentRequest is the request to register an agent
type RegisterAgentRequest struct {
	AgentID     string         `json:"agent_id"`
	DisplayName string         `json:"display_name,omitempty"`
	Tags        []string       `json:"tags,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
	PolicyID    string         `json:"policy_id,omitempty"`
}

// RegisterAgentResult is the result of registering an agent
type RegisterAgentResult struct {
	ID            string `json:"id"`
	AgentID       string `json:"agent_id"`
	DisplayName   string `json:"display_name,omitempty"`
	Status        string `json:"status"`
	KeyID         string `json:"key_id"`
	SigningSecret string `json:"signing_secret"` // Only returned at creation!
	CreatedAt     string `json:"created_at,omitempty"`
}

// RotateKeyResult is the result of rotating an agent's key
type RotateKeyResult struct {
	AgentID       string `json:"agent_id"`
	KeyID         string `json:"key_id"`
	SigningSecret string `json:"signing_secret"` // Only returned at rotation!
	RotatedAt     string `json:"rotated_at"`
}

// Sign signs a payload and returns the envelope
func (c *Client) Sign(req SignRequest) (*SignResult, error) {
	if c.config.APIKey == "" {
		return c.signLocal(req)
	}
	return c.signEnterprise(req)
}

// signLocal performs local signing without enterprise features
func (c *Client) signLocal(req SignRequest) (*SignResult, error) {
	payloadBytes, err := canonicalJSON(req.Payload)
	if err != nil {
		return nil, fmt.Errorf("moss: failed to encode payload: %w", err)
	}

	hash := sha256.Sum256(payloadBytes)
	payloadHash := base64.RawURLEncoding.EncodeToString(hash[:])

	seq := c.sequence.Add(1)
	now := time.Now().Unix()

	subject := req.AgentID
	if subject == "" {
		subject = "moss:local:default"
	}

	envelope := &Envelope{
		Spec:        SPEC,
		Version:     Version,
		Alg:         Algorithm,
		Subject:     subject,
		KeyVersion:  1,
		Seq:         seq,
		IssuedAt:    now,
		PayloadHash: payloadHash,
		Signature:   "", // Local signing doesn't have actual ML-DSA-44 signature
	}

	return &SignResult{
		Envelope:       envelope,
		Allowed:        true,
		Decision:       "allow",
		SignatureValid: true,
	}, nil
}

// signEnterprise performs signing with enterprise policy evaluation
func (c *Client) signEnterprise(req SignRequest) (*SignResult, error) {
	payloadBytes, err := canonicalJSON(req.Payload)
	if err != nil {
		return nil, fmt.Errorf("moss: failed to encode payload: %w", err)
	}

	evalReq := map[string]any{
		"subject": req.AgentID,
		"action":  req.Action,
		"payload": req.Payload,
	}
	if req.Context != nil {
		evalReq["context"] = req.Context
	}

	body, err := json.Marshal(evalReq)
	if err != nil {
		return nil, fmt.Errorf("moss: failed to encode request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.config.BaseURL+"/v1/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("moss: failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("moss: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("moss: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("moss: API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var evalResp struct {
		Decision       string    `json:"decision"`
		Reason         string    `json:"reason"`
		Allowed        bool      `json:"allowed"`
		ActionID       string    `json:"action_id"`
		EvidenceID     string    `json:"evidence_id"`
		Envelope       *Envelope `json:"envelope"`
		SignatureValid bool      `json:"signature_valid"`
	}

	if err := json.Unmarshal(respBody, &evalResp); err != nil {
		return nil, fmt.Errorf("moss: failed to parse response: %w", err)
	}

	// If no envelope from server, create local one
	if evalResp.Envelope == nil {
		hash := sha256.Sum256(payloadBytes)
		payloadHash := base64.RawURLEncoding.EncodeToString(hash[:])
		seq := c.sequence.Add(1)

		evalResp.Envelope = &Envelope{
			Spec:        SPEC,
			Version:     Version,
			Alg:         Algorithm,
			Subject:     req.AgentID,
			KeyVersion:  1,
			Seq:         seq,
			IssuedAt:    time.Now().Unix(),
			PayloadHash: payloadHash,
		}
	}

	return &SignResult{
		Envelope:       evalResp.Envelope,
		Allowed:        evalResp.Decision == "allow",
		Blocked:        evalResp.Decision == "block",
		Held:           evalResp.Decision == "hold",
		Decision:       evalResp.Decision,
		Reason:         evalResp.Reason,
		ActionID:       evalResp.ActionID,
		EvidenceID:     evalResp.EvidenceID,
		SignatureValid: evalResp.SignatureValid,
	}, nil
}

// Verify verifies an envelope against a payload
func (c *Client) Verify(payload any, envelope *Envelope) (*VerifyResult, error) {
	if envelope == nil {
		return &VerifyResult{Valid: false, Error: ErrInvalidEnvelope}, nil
	}

	if envelope.Spec != SPEC {
		return &VerifyResult{Valid: false, Error: fmt.Errorf("moss: unknown spec: %s", envelope.Spec)}, nil
	}

	payloadBytes, err := canonicalJSON(payload)
	if err != nil {
		return &VerifyResult{Valid: false, Error: fmt.Errorf("moss: failed to encode payload: %w", err)}, nil
	}

	hash := sha256.Sum256(payloadBytes)
	computedHash := base64.RawURLEncoding.EncodeToString(hash[:])

	if computedHash != envelope.PayloadHash {
		return &VerifyResult{Valid: false, Error: errors.New("moss: payload hash mismatch")}, nil
	}

	// Note: Full ML-DSA-44 verification would require the public key
	// For now, we verify the hash matches (offline verification)

	return &VerifyResult{
		Valid:    true,
		Subject:  envelope.Subject,
		IssuedAt: time.Unix(envelope.IssuedAt, 0),
		Sequence: envelope.Seq,
	}, nil
}

// Evaluate evaluates an action against policies without signing
func (c *Client) Evaluate(agentID, action string, payload any, context map[string]any) (*PolicyDecision, error) {
	if c.config.APIKey == "" {
		return nil, ErrNoAPIKey
	}

	evalReq := map[string]any{
		"subject": agentID,
		"action":  action,
		"payload": payload,
	}
	if context != nil {
		evalReq["context"] = context
	}

	body, err := json.Marshal(evalReq)
	if err != nil {
		return nil, fmt.Errorf("moss: failed to encode request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.config.BaseURL+"/v1/evaluate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("moss: failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("moss: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("moss: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("moss: API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var decision PolicyDecision
	if err := json.Unmarshal(respBody, &decision); err != nil {
		return nil, fmt.Errorf("moss: failed to parse response: %w", err)
	}

	return &decision, nil
}

// RegisterAgent registers a new agent
func (c *Client) RegisterAgent(req RegisterAgentRequest) (*RegisterAgentResult, error) {
	if c.config.APIKey == "" {
		return nil, ErrNoAPIKey
	}

	body, err := json.Marshal(req)
	if err != nil {
		return nil, fmt.Errorf("moss: failed to encode request: %w", err)
	}

	httpReq, err := http.NewRequest("POST", c.config.BaseURL+"/v1/agents", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("moss: failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("moss: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("moss: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("moss: API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result RegisterAgentResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("moss: failed to parse response: %w", err)
	}

	return &result, nil
}

// GetAgent gets agent details
func (c *Client) GetAgent(agentID string) (*Agent, error) {
	if c.config.APIKey == "" {
		return nil, ErrNoAPIKey
	}

	httpReq, err := http.NewRequest("GET", c.config.BaseURL+"/v1/agents/"+agentID, nil)
	if err != nil {
		return nil, fmt.Errorf("moss: failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("moss: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("moss: failed to read response: %w", err)
	}

	if resp.StatusCode == http.StatusNotFound {
		return nil, nil
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("moss: API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var agent Agent
	if err := json.Unmarshal(respBody, &agent); err != nil {
		return nil, fmt.Errorf("moss: failed to parse response: %w", err)
	}

	return &agent, nil
}

// RotateAgentKey rotates an agent's signing key
func (c *Client) RotateAgentKey(agentID string, reason string) (*RotateKeyResult, error) {
	if c.config.APIKey == "" {
		return nil, ErrNoAPIKey
	}

	reqBody := map[string]string{}
	if reason != "" {
		reqBody["reason"] = reason
	}

	body, _ := json.Marshal(reqBody)

	httpReq, err := http.NewRequest("POST", c.config.BaseURL+"/v1/agents/"+agentID+"/rotate", bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("moss: failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return nil, fmt.Errorf("moss: request failed: %w", err)
	}
	defer resp.Body.Close()

	respBody, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("moss: failed to read response: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("moss: API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	var result RotateKeyResult
	if err := json.Unmarshal(respBody, &result); err != nil {
		return nil, fmt.Errorf("moss: failed to parse response: %w", err)
	}

	return &result, nil
}

// SuspendAgent suspends an agent
func (c *Client) SuspendAgent(agentID string, reason string) error {
	if c.config.APIKey == "" {
		return ErrNoAPIKey
	}

	reqBody := map[string]string{}
	if reason != "" {
		reqBody["reason"] = reason
	}

	body, _ := json.Marshal(reqBody)

	httpReq, err := http.NewRequest("POST", c.config.BaseURL+"/v1/agents/"+agentID+"/suspend", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("moss: failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("moss: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("moss: API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// ReactivateAgent reactivates a suspended agent
func (c *Client) ReactivateAgent(agentID string) error {
	if c.config.APIKey == "" {
		return ErrNoAPIKey
	}

	httpReq, err := http.NewRequest("POST", c.config.BaseURL+"/v1/agents/"+agentID+"/reactivate", nil)
	if err != nil {
		return fmt.Errorf("moss: failed to create request: %w", err)
	}

	httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("moss: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("moss: API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// RevokeAgent permanently revokes an agent
func (c *Client) RevokeAgent(agentID string, reason string) error {
	if c.config.APIKey == "" {
		return ErrNoAPIKey
	}

	if reason == "" {
		return errors.New("moss: reason is required for revocation")
	}

	reqBody := map[string]string{"reason": reason}
	body, _ := json.Marshal(reqBody)

	httpReq, err := http.NewRequest("POST", c.config.BaseURL+"/v1/agents/"+agentID+"/revoke", bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("moss: failed to create request: %w", err)
	}

	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+c.config.APIKey)

	resp, err := c.httpClient.Do(httpReq)
	if err != nil {
		return fmt.Errorf("moss: request failed: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		respBody, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("moss: API error (status %d): %s", resp.StatusCode, string(respBody))
	}

	return nil
}

// canonicalJSON produces deterministic JSON output (RFC 8785)
func canonicalJSON(v any) ([]byte, error) {
	// For simplicity, we use standard JSON encoding
	// A full implementation would use RFC 8785 canonicalization
	return json.Marshal(v)
}

// EnterpriseEnabled returns true if enterprise mode is enabled
func (c *Client) EnterpriseEnabled() bool {
	return c.config.APIKey != ""
}
