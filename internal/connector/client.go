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
func (c *Client) MarkDone(jobID string) error {
	return c.post("/api/v1/connector/jobs/"+jobID+"/done", nil, nil)
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
