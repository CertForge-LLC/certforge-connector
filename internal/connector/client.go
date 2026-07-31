package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"
)

// Job is a pending renewal job returned by the CertForge connector API.
// All device connection details are included — no yaml device list needed.
type Job struct {
	ID          string `json:"id"`
	DeviceID    string `json:"device_id"`
	DeviceName  string `json:"device_name"`
	DeviceType  string `json:"device_type"`
	Status      string `json:"status"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	TLSContext  int    `json:"tls_context"`
	SkipVerify  bool   `json:"skip_verify"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	Certificate string `json:"certificate"` // populated when status=cert_ready
}

// RemoteDevice is a device entry returned by the CertForge connector devices API.
// Used for background cert reads; no credentials included.
type RemoteDevice struct {
	ID         string `json:"id"`
	Type       string `json:"type"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	TLSContext int    `json:"tls_context"`
	SkipVerify bool   `json:"skip_verify"`
}

// Client talks to the CertForge connector REST API.
type Client struct {
	baseURL string
	apiKey  string
	http    *http.Client
}

func NewClient(baseURL, apiKey string) *Client {
	return &Client{
		baseURL: baseURL,
		apiKey:  apiKey,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// PollJobs returns pending jobs for this connector's org.
func (c *Client) PollJobs() ([]Job, error) {
	var jobs []Job
	if err := c.get("/api/v1/connector/jobs", &jobs); err != nil {
		return nil, err
	}
	return jobs, nil
}

// GetDevices returns all devices registered in CertForge for this org.
// Used for background cert discovery — no credentials included.
func (c *Client) GetDevices() ([]RemoteDevice, error) {
	var devices []RemoteDevice
	if err := c.get("/api/v1/connector/devices", &devices); err != nil {
		return nil, err
	}
	return devices, nil
}

// GetJob returns the current state of a single job.
func (c *Client) GetJob(id string) (*Job, error) {
	var job Job
	if err := c.get("/api/v1/connector/jobs/"+id, &job); err != nil {
		return nil, err
	}
	return &job, nil
}

// SubmitCSR posts a CSR for the given job. CertForge signs it and returns the cert.
func (c *Client) SubmitCSR(jobID, csrPEM string) (*Job, error) {
	body, _ := json.Marshal(map[string]string{"csr": csrPEM})
	var job Job
	if err := c.post("/api/v1/connector/jobs/"+jobID+"/csr", body, &job); err != nil {
		return nil, err
	}
	return &job, nil
}

// MarkDone tells CertForge the certificate was successfully installed.
// certPEM is optional: when non-empty (local CA signing path), CertForge stores
// the cert for inventory and fires the cert_signed audit event.
func (c *Client) MarkDone(jobID, certPEM string) error {
	var body []byte
	if certPEM != "" {
		body, _ = json.Marshal(map[string]string{"certificate": certPEM})
	}
	return c.post("/api/v1/connector/jobs/"+jobID+"/done", body, nil)
}

// ConnectorScope is the sync scope for a private CA connector, fetched from CertForge.
type ConnectorScope struct {
	Domains        []string `json:"domains"`
	EKU            []string `json:"eku"`
	IncludeExpired bool     `json:"include_expired"`
	IssuedAfter    string   `json:"issued_after"`
	SyncInterval   string   `json:"sync_interval"`
}

// CAConnectorInfo is a CA connector record returned by CertForge.
type CAConnectorInfo struct {
	ID    string         `json:"id"`
	Name  string         `json:"name"`
	Scope ConnectorScope `json:"scope"`
}

// InventoryCert is a single cert record for the inventory push API.
type InventoryCert struct {
	Serial    string   `json:"serial"`
	Issuer    string   `json:"issuer"`
	Subject   string   `json:"subject"`
	SANs      []string `json:"sans"`
	EKU       []string `json:"eku"`
	NotBefore string   `json:"not_before"`
	NotAfter  string   `json:"not_after"`
	CertPEM   string   `json:"cert_pem"`
}

// GetCAConnectors returns CA connectors of type "connector" configured for this org.
// The agent calls this to discover which private CAs it should sync and fetch scope.
func (c *Client) GetCAConnectors() ([]CAConnectorInfo, error) {
	var out []CAConnectorInfo
	if err := c.get("/api/v1/connector/ca-connectors", &out); err != nil {
		return nil, err
	}
	return out, nil
}

// PushInventory sends a batch of cert records to CertForge for a specific CA connector.
// Returns the number of certs accepted by the server.
func (c *Client) PushInventory(connectorID string, certs []InventoryCert) (int, error) {
	body, _ := json.Marshal(map[string]any{"certs": certs})
	var result struct {
		OK    bool `json:"ok"`
		Count int  `json:"count"`
	}
	if err := c.post("/api/v1/connector/ca-connectors/"+connectorID+"/inventory", body, &result); err != nil {
		return 0, err
	}
	return result.Count, nil
}

// LocalSignAuth is the response from CertForge's authorize-local-signing endpoint.
type LocalSignAuth struct {
	Approved      bool   `json:"approved"`
	Reason        string `json:"reason,omitempty"`        // set when approved=false
	CAConnectorID string `json:"ca_connector_id,omitempty"` // which local CA to sign with
	ValidityDays  int    `json:"validity_days,omitempty"`
	DTPID         string `json:"dtp_id,omitempty"`
}

// AuthorizeLocalSigning calls CertForge to validate that the job's domain is covered
// by a DTP pointing to a private_connector CA, enforces policy, and records the
// approval server-side. The connector must call this before signing locally.
// Fail-closed: if this returns an error or Approved==false, do not sign.
func (c *Client) AuthorizeLocalSigning(jobID, cn string, sans []string, keyAlgorithm string, keyBits int) (*LocalSignAuth, error) {
	body, _ := json.Marshal(map[string]any{
		"cn":            cn,
		"sans":          sans,
		"key_algorithm": keyAlgorithm,
		"key_bits":      keyBits,
	})
	var result LocalSignAuth
	// A 422 (denied) is a valid JSON response, not a transport error — decode it.
	req, err := http.NewRequest(http.MethodPost, c.baseURL+"/api/v1/connector/jobs/"+jobID+"/authorize-local-signing", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, fmt.Errorf("authorize-local-signing: %w", err)
	}
	defer resp.Body.Close()
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err := json.Unmarshal(b, &result); err != nil {
		return nil, fmt.Errorf("authorize-local-signing: decode response: %w", err)
	}
	return &result, nil
}

// ReportCert tells CertForge the current certificate expiry, CN, and SANs from
// a device's live TLS cert. CertForge uses this for baseline visibility and DTP matching.
func (c *Client) ReportCert(deviceID string, info CertInfo) error {
	body, _ := json.Marshal(map[string]any{
		"not_after": info.NotAfter.UTC().Format(time.RFC3339),
		"cn":        info.CN,
		"sans":      info.SANs,
	})
	return c.post("/api/v1/connector/devices/"+deviceID+"/cert", body, nil)
}

func (c *Client) get(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, c.baseURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("GET %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("GET %s: %s %s", path, resp.Status, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

func (c *Client) post(path string, body []byte, out any) error {
	var bodyReader io.Reader
	if body != nil {
		bodyReader = bytes.NewReader(body)
	}
	req, err := http.NewRequest(http.MethodPost, c.baseURL+path, bodyReader)
	if err != nil {
		return err
	}
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return fmt.Errorf("POST %s: %w", path, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return fmt.Errorf("POST %s: %s %s", path, resp.Status, b)
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}
