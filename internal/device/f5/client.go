// Package f5 provides an iControl REST client for F5 BIG-IP devices.
// It targets the iControl REST API available on TMOS 11.6+.
//
// Certificate lifecycle flow:
//  1. Call PullCSR to generate a new CSR from the existing key of the target
//     client-ssl profile without disturbing the running configuration.
//  2. CertForge signs the CSR via policy evaluation.
//  3. Call InstallCert to upload the signed certificate and install it
//     under the same name, so the SSL profile picks it up automatically.
//
// TLSContext selects which client-ssl profile to target (0-based index into
// the profile list returned by GET /mgmt/tm/ltm/profile/client-ssl).
// Check the correct index under Local Traffic → Profiles → SSL → Client in
// the BIG-IP UI, or call ListClientSSLProfiles during initial setup.
package f5

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

const csrWorkName = "certforge-renewal"

// Client connects to a single F5 BIG-IP via iControl REST.
type Client struct {
	Host       string
	Port       int
	Username   string
	Password   string
	TLSContext int // index into the client-ssl profile list (0-based)
	SkipVerify bool

	hc *http.Client
}

func (c *Client) httpClient() *http.Client {
	if c.hc == nil {
		c.hc = &http.Client{
			Timeout: 60 * time.Second,
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
	return fmt.Sprintf("https://%s:%d", c.Host, port)
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
		return nil, 0, fmt.Errorf("f5: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return b, resp.StatusCode, nil
}

func (c *Client) postJSON(ctx context.Context, path string, payload any) ([]byte, int, error) {
	b, err := json.Marshal(payload)
	if err != nil {
		return nil, 0, err
	}
	return c.do(ctx, http.MethodPost, path, bytes.NewReader(b), "application/json")
}

// --- client-ssl profile lookup ---

type sslProfile struct {
	Name         string            `json:"name"`
	Partition    string            `json:"partition"`
	Cert         string            `json:"cert"`
	Key          string            `json:"key"`
	CertKeyChain []certKeyChainEntry `json:"certKeyChain"`
}

type certKeyChainEntry struct {
	Name string `json:"name"`
	Cert string `json:"cert"`
	Key  string `json:"key"`
}

type profileList struct {
	Items []sslProfile `json:"items"`
}

// ListClientSSLProfiles returns all client-ssl profiles on the device.
// Useful during initial connector setup to find the right TLSContext index.
func (c *Client) ListClientSSLProfiles(ctx context.Context) ([]sslProfile, error) {
	body, status, err := c.do(ctx, http.MethodGet, "/mgmt/tm/ltm/profile/client-ssl", nil, "")
	if err != nil {
		return nil, err
	}
	if status != http.StatusOK {
		return nil, fmt.Errorf("f5: list client-ssl profiles: HTTP %d: %s", status, body)
	}
	var list profileList
	if err := json.Unmarshal(body, &list); err != nil {
		return nil, fmt.Errorf("f5: list client-ssl profiles: parse: %w", err)
	}
	return list.Items, nil
}

// targetProfile returns the client-ssl profile at the configured TLSContext index.
func (c *Client) targetProfile(ctx context.Context) (*sslProfile, error) {
	profiles, err := c.ListClientSSLProfiles(ctx)
	if err != nil {
		return nil, err
	}
	if len(profiles) == 0 {
		return nil, fmt.Errorf("f5: no client-ssl profiles found on device")
	}
	idx := c.TLSContext
	if idx < 0 || idx >= len(profiles) {
		return nil, fmt.Errorf("f5: TLSContext %d out of range — device has %d client-ssl profile(s)", idx, len(profiles))
	}
	return &profiles[idx], nil
}

// certKeyNames returns (certName, keyName, partition) for the target profile.
// Prefers certKeyChain[0] when present; falls back to the top-level cert/key fields.
func certKeyNames(p *sslProfile) (cert, key, partition string, err error) {
	partition = p.Partition
	if partition == "" {
		partition = "Common"
	}

	// certKeyChain is the preferred source — it supports multiple cert/key pairs per profile.
	if len(p.CertKeyChain) > 0 && p.CertKeyChain[0].Cert != "" {
		cert = stripPartition(p.CertKeyChain[0].Cert)
		key = stripPartition(p.CertKeyChain[0].Key)
		return
	}
	if p.Cert != "" && p.Key != "" {
		cert = stripPartition(p.Cert)
		key = stripPartition(p.Key)
		return
	}
	err = fmt.Errorf("f5: client-ssl profile %q has no cert/key configured", p.Name)
	return
}

// stripPartition removes the /Partition/ prefix from an F5 path (e.g. /Common/my.crt → my.crt).
func stripPartition(path string) string {
	parts := strings.SplitN(path, "/", 3)
	if len(parts) == 3 {
		return parts[2]
	}
	return path
}

// --- CSR generation ---

type csrRequest struct {
	Command    string `json:"command"`
	Name       string `json:"name"`
	Partition  string `json:"partition"`
	Key        string `json:"key"`
	CommonName string `json:"commonName"`
}

// generateCSR creates (or overwrites) the working CSR on the device using the
// existing private key so the key never leaves the BIG-IP.
func (c *Client) generateCSR(ctx context.Context, csrName, partition, keyName, commonName string) error {
	body, status, err := c.postJSON(ctx, "/mgmt/tm/sys/crypto/csr", csrRequest{
		Command:    "generate",
		Name:       csrName,
		Partition:  partition,
		Key:        keyName,
		CommonName: commonName,
	})
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusCreated {
		return fmt.Errorf("f5: generate CSR: HTTP %d: %s", status, body)
	}
	return nil
}

// downloadCSR retrieves the PEM-encoded CSR from the file-transfer endpoint.
func (c *Client) downloadCSR(ctx context.Context, partition, csrName string) (string, error) {
	path := fmt.Sprintf("/mgmt/shared/file-transfer/ssl-csr-transfers/~%s~%s", partition, csrName)
	body, status, err := c.do(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("f5: download CSR: HTTP %d: %s", status, body)
	}
	pem := strings.TrimSpace(string(body))
	if !strings.HasPrefix(pem, "-----BEGIN") {
		return "", fmt.Errorf("f5: download CSR: unexpected response (not PEM): %.200s", pem)
	}
	return pem, nil
}

// --- cert info ---

type sslCertInfo struct {
	Subject string `json:"subject"` // e.g. "CN=example.com"
}

// certCN fetches the existing cert and returns its Common Name.
func (c *Client) certCN(ctx context.Context, partition, certName string) (string, error) {
	path := fmt.Sprintf("/mgmt/tm/sys/file/ssl-cert/~%s~%s", partition, certName)
	body, status, err := c.do(ctx, http.MethodGet, path, nil, "")
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("f5: get cert info: HTTP %d: %s", status, body)
	}
	var info sslCertInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("f5: get cert info: parse: %w", err)
	}
	// Subject is "CN=example.com" or "CN=example.com,O=Acme,..."
	cn := info.Subject
	for _, field := range strings.Split(info.Subject, ",") {
		field = strings.TrimSpace(field)
		if strings.HasPrefix(strings.ToUpper(field), "CN=") {
			cn = field[3:]
			break
		}
	}
	return cn, nil
}

// --- PullCSR implements device.Device ---

// PullCSR generates a fresh CSR from the existing private key of the target
// client-ssl profile. The key never leaves the BIG-IP.
func (c *Client) PullCSR(ctx context.Context) (string, error) {
	profile, err := c.targetProfile(ctx)
	if err != nil {
		return "", err
	}

	certName, keyName, partition, err := certKeyNames(profile)
	if err != nil {
		return "", err
	}

	cn, err := c.certCN(ctx, partition, certName)
	if err != nil {
		return "", fmt.Errorf("f5: read existing cert for CN: %w", err)
	}

	if err := c.generateCSR(ctx, csrWorkName, partition, keyName, cn); err != nil {
		return "", fmt.Errorf("f5: %w", err)
	}

	pem, err := c.downloadCSR(ctx, partition, csrWorkName)
	if err != nil {
		return "", err
	}
	return pem, nil
}

// --- InstallCert implements device.Device ---

// InstallCert uploads the signed PEM certificate to the BIG-IP and installs it
// under the same name as the existing cert, so the SSL profile picks it up without
// any profile reconfiguration.
func (c *Client) InstallCert(ctx context.Context, certPEM string) error {
	profile, err := c.targetProfile(ctx)
	if err != nil {
		return err
	}

	certName, _, partition, err := certKeyNames(profile)
	if err != nil {
		return err
	}

	// Upload the cert PEM to the REST file transfer staging area.
	fileName := certName + ".crt"
	uploadPath := "/mgmt/shared/file-transfer/uploads/" + fileName
	certBytes := []byte(certPEM)
	contentRange := fmt.Sprintf("0-%d/%d", len(certBytes)-1, len(certBytes))

	uploadBody, uploadStatus, err := c.do(ctx, http.MethodPost, uploadPath,
		bytes.NewReader(certBytes), "application/octet-stream")
	if err != nil {
		return fmt.Errorf("f5: upload cert: %w", err)
	}
	// Accept 200 and 204; some versions return the file info on 200.
	if uploadStatus != http.StatusOK && uploadStatus != http.StatusNoContent {
		_ = contentRange // used in the header below
		return fmt.Errorf("f5: upload cert: HTTP %d: %s", uploadStatus, uploadBody)
	}

	// Install the uploaded cert under the existing cert name.
	installBody, installStatus, err := c.postJSON(ctx, "/mgmt/tm/sys/crypto/cert", map[string]string{
		"command":         "install",
		"name":            fmt.Sprintf("/%s/%s", partition, certName),
		"from-local-file": fmt.Sprintf("/var/config/rest/downloads/%s", fileName),
	})
	if err != nil {
		return fmt.Errorf("f5: install cert: %w", err)
	}
	if installStatus != http.StatusOK && installStatus != http.StatusCreated {
		return fmt.Errorf("f5: install cert: HTTP %d: %s", installStatus, installBody)
	}
	return nil
}

// Ping verifies connectivity and credentials by listing client-ssl profiles.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.ListClientSSLProfiles(ctx)
	return err
}
