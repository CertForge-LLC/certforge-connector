// Package audiocodes provides a REST client for AudioCodes Mediant VE SBCs.
// It targets the /api/v1 REST interface present on Mediant firmware 7.2+.
//
// Certificate lifecycle flow:
//  1. Call PullCSR to retrieve the pending CSR from a TLS context.
//  2. CertForge signs the CSR via policy evaluation.
//  3. Call InstallCert to push the signed certificate back to the device.
//
// NOTE: The exact REST endpoints for CSR operations vary by firmware version.
// Verify against your device's REST API browser at https://<host>/api/v1/browserapp.
package audiocodes

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// Client connects to a single Mediant VE device.
type Client struct {
	Host       string
	Port       int
	Username   string
	Password   string
	TLSContext int
	SkipVerify bool

	hc *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.hc == nil {
		c.hc = &http.Client{
			Timeout: 30 * time.Second,
			Transport: &http.Transport{
				TLSClientConfig: &tls.Config{InsecureSkipVerify: c.SkipVerify}, //nolint:gosec
			},
		}
	}
	return c.hc
}

func (c *Client) base() string {
	port := c.Port
	if port == 0 {
		port = 443
	}
	return fmt.Sprintf("https://%s:%d/api/v1", c.Host, port)
}

func (c *Client) do(ctx context.Context, method, path string, body io.Reader, contentType string) ([]byte, int, error) {
	url := c.base() + path
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, 0, err
	}
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("audiocodes: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return b, resp.StatusCode, nil
}

// TLSContext describes a single TLS context on the device.
type TLSContextInfo struct {
	Index int    `json:"TLSContextIndex"`
	Name  string `json:"TLSContextName"`
}

// ListTLSContexts returns all TLS contexts configured on the device.
func (c *Client) ListTLSContexts(ctx context.Context) ([]TLSContextInfo, error) {
	body, status, err := c.do(ctx, http.MethodGet, "/files/TLSContext", nil, "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("audiocodes: ListTLSContexts: HTTP %d: %s", status, body)
	}

	// Mediant returns {"TLSContext": [...]} or a flat array depending on firmware.
	var envelope struct {
		TLSContext []TLSContextInfo `json:"TLSContext"`
	}
	if err := json.Unmarshal(body, &envelope); err != nil {
		var flat []TLSContextInfo
		if err2 := json.Unmarshal(body, &flat); err2 != nil {
			return nil, fmt.Errorf("audiocodes: ListTLSContexts: parse: %w", err)
		}
		return flat, nil
	}
	return envelope.TLSContext, nil
}

// PullCSR retrieves the Certificate Signing Request for the configured TLS context.
// Implements device.Device.
func (c *Client) PullCSR(ctx context.Context) (string, error) {
	path := fmt.Sprintf("/files/TLSContext/%d/CSR", c.TLSContext)
	body, status, err := c.do(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return "", err
	}
	if status == http.StatusNotFound {
		return "", fmt.Errorf("audiocodes: TLS context %d not found or has no CSR — generate a self-signed cert on the device first", c.TLSContext)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("audiocodes: PullCSR: HTTP %d: %s", status, body)
	}

	// Response may be raw PEM or JSON-wrapped.
	text := strings.TrimSpace(string(body))
	if strings.HasPrefix(text, "-----BEGIN") {
		return text, nil
	}

	// Try JSON unwrap.
	var wrapper struct {
		CSR string `json:"CSR"`
	}
	if err := json.Unmarshal(body, &wrapper); err == nil && wrapper.CSR != "" {
		return wrapper.CSR, nil
	}

	return "", fmt.Errorf("audiocodes: PullCSR: unexpected response format (HTTP %d): %.200s", status, text)
}

// InstallCert pushes a signed PEM certificate to the configured TLS context.
// Implements device.Device.
func (c *Client) InstallCert(ctx context.Context, certPEM string) error {
	path := fmt.Sprintf("/files/TLSContext/%d", c.TLSContext)
	body, status, err := c.do(ctx, http.MethodPut, path,
		strings.NewReader(certPEM), "application/x-pem-file")
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("audiocodes: InstallCert: HTTP %d: %s", status, body)
	}
	return nil
}

// Ping verifies connectivity and credentials by fetching the TLS context list.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.ListTLSContexts(ctx)
	return err
}
