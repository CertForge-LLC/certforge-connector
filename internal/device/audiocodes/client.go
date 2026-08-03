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
	"crypto/md5"  //nolint:gosec — MD5 required by RFC 7616 HTTP Digest Auth
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
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
	rawURL := c.base() + path
	b, status, wwwAuth, err := c.doRaw(ctx, method, rawURL, body, contentType, "")
	if err != nil {
		return nil, 0, err
	}
	// On 401 with no body to replay, attempt HTTP Digest if challenged.
	if status == http.StatusUnauthorized && body == nil {
		if dc := parseDigestChallenge(wwwAuth); dc != nil {
			// Digest auth URI must be the path component only, not the full URL.
			parsed, _ := url.Parse(rawURL)
			auth := c.buildDigestHeader(method, parsed.RequestURI(), dc)
			b, status, _, err = c.doRaw(ctx, method, rawURL, nil, contentType, auth)
			if err != nil {
				return nil, 0, err
			}
		}
	}
	return b, status, nil
}

// doRaw sends a single HTTP request. authOverride, if non-empty, replaces the
// default Basic auth header (used for the Digest auth retry).
func (c *Client) doRaw(ctx context.Context, method, url string, body io.Reader, contentType, authOverride string) ([]byte, int, string, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, body)
	if err != nil {
		return nil, 0, "", err
	}
	if authOverride != "" {
		req.Header.Set("Authorization", authOverride)
	} else {
		req.SetBasicAuth(c.Username, c.Password)
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

// SoftwareVersion returns the device firmware/software version string.
// Implements device.Versioned.
func (c *Client) SoftwareVersion(ctx context.Context) (string, error) {
	body, status, err := c.do(ctx, http.MethodGet, "/", nil, "")
	if err != nil {
		return "", err
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("audiocodes: SoftwareVersion: HTTP %d: %.200s", status, body)
	}
	var info struct {
		SoftwareVersion string `json:"SoftwareVersion"`
	}
	if err := json.Unmarshal(body, &info); err != nil {
		return "", fmt.Errorf("audiocodes: SoftwareVersion: parse: %w", err)
	}
	return info.SoftwareVersion, nil
}

// Ping verifies connectivity and credentials by fetching the TLS context list.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.ListTLSContexts(ctx)
	return err
}
