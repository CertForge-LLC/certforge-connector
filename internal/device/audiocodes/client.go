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
	"bytes"
	"context"
	"crypto/md5"  //nolint:gosec — MD5 required by RFC 7616 HTTP Digest Auth
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/certforge/certforge-connector/internal/device"
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
	rawURL := c.base() + path

	if body != nil {
		// Requests with a body can't be probed — send with Basic auth directly.
		b, status, _, err := c.doRaw(ctx, method, rawURL, body, contentType, "")
		return b, status, err
	}

	// For body-less requests: probe without auth first so the device can issue the
	// correct challenge. Sending preemptive Basic auth causes some devices to reject
	// the request outright without returning a Digest challenge.
	b, status, wwwAuth, err := c.doRaw(ctx, method, rawURL, nil, contentType, "none")
	if err != nil {
		return nil, 0, err
	}
	if status != http.StatusUnauthorized {
		return b, status, nil
	}

	// 401 — authenticate using the challenge the device returned.
	log.Printf("[audiocodes] %s auth challenge: %q", c.Host, wwwAuth)
	parsed, _ := url.Parse(rawURL)
	var auth string // empty → doRaw sends Basic auth
	if dc := parseDigestChallenge(wwwAuth); dc != nil {
		auth = c.buildDigestHeader(method, parsed.RequestURI(), dc)
	}
	b, status, _, err = c.doRaw(ctx, method, rawURL, nil, contentType, auth)
	return b, status, err
}

// doRaw sends a single HTTP request.
// authOverride controls the Authorization header:
//   - ""     → send Basic auth (default)
//   - "none" → send no Authorization header (probe)
//   - other  → use verbatim as the Authorization header value
func (c *Client) doRaw(ctx context.Context, method, rawURL string, body io.Reader, contentType, authOverride string) ([]byte, int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, rawURL, body)
	if err != nil {
		return nil, 0, "", err
	}
	switch authOverride {
	case "none":
		// no Authorization header
	case "":
		req.SetBasicAuth(c.Username, c.Password)
	default:
		req.Header.Set("Authorization", authOverride)
	}
	req.Header.Set("Accept", "application/json")
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, 0, "", fmt.Errorf("audiocodes: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, "", err
	}
	return b, resp.StatusCode, resp.Header.Get("WWW-Authenticate"), nil
}

var digestParamRE = regexp.MustCompile(`(\w+)="([^"]*)"`)

type digestChallenge struct {
	realm, nonce, qop string
}

func parseDigestChallenge(header string) *digestChallenge {
	if !strings.HasPrefix(header, "Digest ") {
		return nil
	}
	dc := &digestChallenge{}
	for _, m := range digestParamRE.FindAllStringSubmatch(header, -1) {
		switch m[1] {
		case "realm":
			dc.realm = m[2]
		case "nonce":
			dc.nonce = m[2]
		case "qop":
			dc.qop = strings.TrimSpace(strings.Split(m[2], ",")[0]) // first listed qop
		}
	}
	if dc.realm == "" || dc.nonce == "" {
		return nil
	}
	return dc
}

func md5s(s string) string { //nolint:gosec
	h := md5.Sum([]byte(s))
	return hex.EncodeToString(h[:])
}

func (c *Client) buildDigestHeader(method, uri string, dc *digestChallenge) string {
	ha1 := md5s(c.Username + ":" + dc.realm + ":" + c.Password)
	ha2 := md5s(method + ":" + uri)
	if dc.qop == "auth" {
		nc, cnonce := "00000001", "cf3b5be8"
		resp := md5s(ha1 + ":" + dc.nonce + ":" + nc + ":" + cnonce + ":" + dc.qop + ":" + ha2)
		return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", algorithm=MD5, qop=%s, nc=%s, cnonce="%s", response="%s"`,
			c.Username, dc.realm, dc.nonce, uri, dc.qop, nc, cnonce, resp)
	}
	resp := md5s(ha1 + ":" + dc.nonce + ":" + ha2)
	return fmt.Sprintf(`Digest username="%s", realm="%s", nonce="%s", uri="%s", response="%s"`,
		c.Username, dc.realm, dc.nonce, uri, resp)
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

// GenerateCSR generates a new private key on the device and returns the CSR PEM.
// POST /api/v1/files/tls/{id}/certificate/request
// Implements device.CSRGenerator — the connector uses this instead of PullCSR.
func (c *Client) GenerateCSR(ctx context.Context, subject device.CertSubject) (string, error) {
	cn := subject.CN
	if cn == "" {
		cn = c.Host
	}
	fields := map[string]any{
		"subjectName":        cn,
		"signatureAlgorithm": "sha256",
	}
	if subject.O != "" {
		fields["companyName"] = subject.O
	}
	if subject.OU != "" {
		fields["organizationalUnit"] = subject.OU
	}
	if subject.L != "" {
		fields["localityName"] = subject.L
	}
	if subject.ST != "" {
		fields["state"] = subject.ST
	}
	if subject.C != "" {
		fields["countryCode"] = subject.C
	}
	payload, _ := json.Marshal(fields)
	path := fmt.Sprintf("/files/tls/%d/certificate/request", c.TLSContext)
	body, status, err := c.do(ctx, http.MethodPost, path, bytes.NewReader(payload), "application/json")
	if err != nil {
		return "", fmt.Errorf("audiocodes: GenerateCSR: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("audiocodes: GenerateCSR: HTTP %d: %s", status, body)
	}
	csr := strings.TrimSpace(string(body))
	if !strings.HasPrefix(csr, "-----BEGIN") {
		return "", fmt.Errorf("audiocodes: GenerateCSR: unexpected response: %.200s", csr)
	}
	return csr, nil
}

// PullCSR satisfies the device.Device interface by calling GenerateCSR with the
// device host as CN. Prefer the CSRGenerator interface path in the worker.
func (c *Client) PullCSR(ctx context.Context) (string, error) {
	return c.GenerateCSR(ctx, device.CertSubject{CN: c.Host})
}

// InstallCert uploads the signed certificate chain to the device's TLS context.
// PUT /api/v1/files/tls/{id}/certificate (multipart/form-data)
// Implements device.Device.
func (c *Client) InstallCert(ctx context.Context, certPEM string) error {
	body, ct, err := pemMultipart(certPEM, "certificate.pem")
	if err != nil {
		return fmt.Errorf("audiocodes: InstallCert: %w", err)
	}
	path := fmt.Sprintf("/files/tls/%d/certificate", c.TLSContext)
	resp, status, err := c.do(ctx, http.MethodPut, path, body, ct)
	if err != nil {
		return fmt.Errorf("audiocodes: InstallCert: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("audiocodes: InstallCert: HTTP %d: %s", status, resp)
	}
	return nil
}

// InstallTrustedRoot adds CA certificates to the device's trusted root store.
// PUT /api/v1/files/tls/{id}/trustedRoot/incremental (multipart/form-data)
// Implements device.TrustedRootInstaller.
func (c *Client) InstallTrustedRoot(ctx context.Context, caPEM string) error {
	body, ct, err := pemMultipart(caPEM, "trusted.pem")
	if err != nil {
		return fmt.Errorf("audiocodes: InstallTrustedRoot: %w", err)
	}
	path := fmt.Sprintf("/files/tls/%d/trustedRoot/incremental", c.TLSContext)
	resp, status, err := c.do(ctx, http.MethodPut, path, body, ct)
	if err != nil {
		return fmt.Errorf("audiocodes: InstallTrustedRoot: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("audiocodes: InstallTrustedRoot: HTTP %d: %s", status, resp)
	}
	return nil
}

// pemMultipart wraps a PEM string in a multipart/form-data body with field name "file".
func pemMultipart(pemData, filename string) (*bytes.Buffer, string, error) {
	var buf bytes.Buffer
	mw := multipart.NewWriter(&buf)
	fw, err := mw.CreateFormFile("file", filename)
	if err != nil {
		return nil, "", err
	}
	fmt.Fprint(fw, pemData)
	mw.Close()
	return &buf, mw.FormDataContentType(), nil
}

// SoftwareVersion returns the device firmware version string from /api/v1/status.
// Implements device.Versioned.
func (c *Client) SoftwareVersion(ctx context.Context) (string, error) {
	body, status, err := c.do(ctx, http.MethodGet, "/status", nil, "")
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("audiocodes: SoftwareVersion: HTTP %d: %.200s", status, body)
	}
	var info struct {
		VersionID string `json:"versionID"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("audiocodes: SoftwareVersion: parse: %w", err)
	}
	return info.VersionID, nil
}

// Ping verifies connectivity and credentials by fetching the TLS context list.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.ListTLSContexts(ctx)
	return err
}
