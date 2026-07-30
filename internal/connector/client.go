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
type Job struct {
	ID          string `json:"id"`
	DeviceID    string `json:"device_id"`
	DeviceName  string `json:"device_name"`
	DeviceType  string `json:"device_type"`
	Status      string `json:"status"`
	Host        string `json:"host"`
	Port        int    `json:"port"`
	TLSContext  int    `json:"tls_context"`
	Certificate string `json:"certificate"` // populated when status=cert_ready
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

// PollJobs returns jobs in pending_csr state for this connector's org.
func (c *Client) PollJobs() ([]Job, error) {
	var jobs []Job
	if err := c.get("/api/v1/connector/jobs", &jobs); err != nil {
		return nil, err
	}
	return jobs, nil
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

// ReportCert tells CertForge the current certificate expiry on a device.
// CertForge uses this to populate cert_not_after and next_expected_at without
// needing a full renewal cycle to have completed first.
func (c *Client) ReportCert(deviceID string, notAfter time.Time) error {
	body, _ := json.Marshal(map[string]string{
		"not_after": notAfter.UTC().Format(time.RFC3339),
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
