// Package ribbon provides a REST client for Ribbon SWE-lite SBCs.
// It targets the /rest API documented at:
// https://publicdoc.rbbn.com/spaces/UXDOC120/pages/325194316/REST+API+User+s+Guide
//
// Certificate lifecycle flow:
//  1. Login — POST /rest/login → session cookie (10-min idle expiry).
//  2. GenerateCSR — POST /rest/csr?action=generate → device creates a new key
//     pair on-board and returns the CSR PEM in the response XML.
//  3. CertForge signs the CSR via policy evaluation.
//  4. InstallCert — POST /rest/certificate/1?action=import → signed PEM is
//     pushed to certificate slot 1 (the server certificate slot).
//  5. Logout — POST /rest/logout.
//
// No explicit save/commit step is required; changes take effect immediately.
// Certificate ID 1 is the server certificate; other IDs are trusted CA certs.
package ribbon

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/certforge/certforge-connector/internal/device"
)

// Client connects to a single Ribbon SWE-lite SBC.
type Client struct {
	Host       string
	Port       int
	Username   string
	Password   string
	SkipVerify bool
	// KeyBits controls the RSA key size for CSR generation: 1024 or 2048.
	// Defaults to 2048 when zero or unset.
	KeyBits int

	hc     *http.Client
	cookie string // cached session cookie value ("name=value")
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
	return fmt.Sprintf("https://%s:%d/rest", c.Host, port)
}

// login authenticates and caches the session cookie.
// The Ribbon REST API requires a session cookie established via POST /rest/login.
// Sessions expire after 10 minutes of idle time; login is called at the start of
// each operation (GenerateCSR, InstallCert) so expiry is never a concern.
func (c *Client) login(ctx context.Context) error {
	vals := url.Values{
		"Username": {c.Username},
		"Password": {c.Password},
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		c.base()+"/login", strings.NewReader(vals.Encode()))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return fmt.Errorf("ribbon: login: %w", err)
	}
	defer resp.Body.Close()
	io.ReadAll(resp.Body) //nolint:errcheck — drain body

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("ribbon: login: HTTP %d (check credentials)", resp.StatusCode)
	}
	// Session token arrives as a Set-Cookie header; extract the first cookie.
	for _, ck := range resp.Cookies() {
		c.cookie = ck.Name + "=" + ck.Value
		return nil
	}
	return fmt.Errorf("ribbon: login: no session cookie in response")
}

func (c *Client) logout(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+"/logout", nil)
	if err == nil {
		req.Header.Set("Cookie", c.cookie)
		resp, err := c.httpClient().Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}
	c.cookie = ""
}

// do sends an authenticated request and returns the raw body.
func (c *Client) do(ctx context.Context, method, path string, body io.Reader, contentType string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Cookie", c.cookie)
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("ribbon: %w", err)
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return b, resp.StatusCode, nil
}

// ribbonResponse is the common XML envelope returned by every Ribbon REST response.
// The status block is present on all responses; the resource block varies.
type ribbonResponse struct {
	HTTPCode   int    `xml:"status>http_code"`
	ErrMessage string `xml:"status>app_status_entry>description"`
	// CSR resource
	CSRContent string `xml:"csr>csrContent"`
	// System resource (firmware version)
	SWVersion string `xml:"system>SWVersion"`
}

// checkStatus returns a non-nil error if the device reported an application-level failure.
func checkStatus(b []byte) (*ribbonResponse, error) {
	var r ribbonResponse
	if err := xml.Unmarshal(b, &r); err != nil {
		// Not all responses are well-formed XML (e.g. 204 No Content) — ignore parse errors
		// and let the HTTP status code be the authority.
		return &r, nil
	}
	if r.HTTPCode != 0 && r.HTTPCode != http.StatusOK {
		return &r, fmt.Errorf("device status %d: %s", r.HTTPCode, r.ErrMessage)
	}
	return &r, nil
}

// GenerateCSR asks the device to generate a new RSA key pair on-board and
// returns the resulting PEM-encoded CSR.
// POST /rest/csr?action=generate
// Implements device.CSRGenerator — the connector worker calls this instead of
// PullCSR when the interface is available, so no pre-existing key or CSR is
// required on the device.
func (c *Client) GenerateCSR(ctx context.Context, subject device.CertSubject) (string, error) {
	if err := c.login(ctx); err != nil {
		return "", err
	}
	defer c.logout(ctx)

	cn := subject.CN
	if cn == "" {
		cn = c.Host
	}
	keyBits := c.KeyBits
	if keyBits != 1024 {
		keyBits = 2048 // safe default; 1024 is supported but not recommended
	}

	vals := url.Values{
		"commonName":   {cn},
		"keyBitLength": {fmt.Sprintf("%d", keyBits)},
	}
	// sanDNS accepts a comma-separated list of FQDNs.
	if len(subject.SANs) > 0 {
		vals.Set("sanDNS", strings.Join(subject.SANs, ","))
	}
	if subject.O != "" {
		vals.Set("organizationName", subject.O)
	}
	if subject.OU != "" {
		vals.Set("organizationalUnitName", subject.OU)
	}
	if subject.L != "" {
		vals.Set("localityName", subject.L)
	}
	if subject.ST != "" {
		vals.Set("stateOrProvinceName", subject.ST)
	}
	if subject.C != "" {
		vals.Set("countryName", subject.C)
	}

	b, status, err := c.do(ctx, http.MethodPost, "/csr?action=generate",
		strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return "", fmt.Errorf("ribbon: GenerateCSR: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("ribbon: GenerateCSR: HTTP %d: %s", status, b)
	}

	resp, err := checkStatus(b)
	if err != nil {
		return "", fmt.Errorf("ribbon: GenerateCSR: %w", err)
	}
	csr := strings.TrimSpace(resp.CSRContent)
	if !strings.HasPrefix(csr, "-----BEGIN") {
		return "", fmt.Errorf("ribbon: GenerateCSR: unexpected response body (%.200s) — verify firmware supports REST CSR generation", b)
	}
	log.Printf("[ribbon] CSR generated on %s (CN=%s, keyBits=%d)", c.Host, cn, keyBits)
	return csr, nil
}

// PullCSR satisfies device.Device by calling GenerateCSR with the device host
// as the Common Name. The connector worker prefers the CSRGenerator interface
// path when the subject is known; PullCSR is the fallback.
func (c *Client) PullCSR(ctx context.Context) (string, error) {
	return c.GenerateCSR(ctx, device.CertSubject{CN: c.Host})
}

// InstallCert uploads a signed PEM certificate to slot 1, the server certificate
// slot on Ribbon SWE-lite devices. Certificate IDs ≥2 are trusted CA certs.
// POST /rest/certificate/1?action=import
// CertFileOperation=1 selects copy-and-paste mode (base64 PEM in CertFileContent).
// Implements device.Device.
func (c *Client) InstallCert(ctx context.Context, certPEM string) error {
	if err := c.login(ctx); err != nil {
		return err
	}
	defer c.logout(ctx)

	vals := url.Values{
		"CertFileOperation": {"1"}, // certOperationCopyAndPaste
		"CertFileContent":   {base64.StdEncoding.EncodeToString([]byte(certPEM))},
		"CertFileName":      {"server.pem"},
	}
	b, status, err := c.do(ctx, http.MethodPost, "/certificate/1?action=import",
		strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return fmt.Errorf("ribbon: InstallCert: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("ribbon: InstallCert: HTTP %d: %s", status, b)
	}
	if _, err := checkStatus(b); err != nil {
		return fmt.Errorf("ribbon: InstallCert: %w", err)
	}
	log.Printf("[ribbon] certificate installed on %s", c.Host)
	return nil
}

// InstallTrustedRoot uploads a CA certificate (or chain) to certificate slot 2,
// the first trusted CA slot on Ribbon devices (slot 1 is the server cert).
// POST /rest/certificate/2?action=import
// Implements device.TrustedRootInstaller — called automatically by the connector
// worker after InstallCert when the signing CA chain is available.
func (c *Client) InstallTrustedRoot(ctx context.Context, caPEM string) error {
	if err := c.login(ctx); err != nil {
		return err
	}
	defer c.logout(ctx)

	vals := url.Values{
		"CertFileOperation": {"1"}, // certOperationCopyAndPaste
		"CertFileContent":   {base64.StdEncoding.EncodeToString([]byte(caPEM))},
		"CertFileName":      {"ca-chain.pem"},
	}
	b, status, err := c.do(ctx, http.MethodPost, "/certificate/2?action=import",
		strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded")
	if err != nil {
		return fmt.Errorf("ribbon: InstallTrustedRoot: %w", err)
	}
	if status != http.StatusOK && status != http.StatusNoContent {
		return fmt.Errorf("ribbon: InstallTrustedRoot: HTTP %d: %s", status, b)
	}
	if _, err := checkStatus(b); err != nil {
		return fmt.Errorf("ribbon: InstallTrustedRoot: %w", err)
	}
	log.Printf("[ribbon] trusted CA chain installed on %s", c.Host)
	return nil
}

// SoftwareVersion returns the running firmware version string.
// GET /rest/system
// Implements device.Versioned.
func (c *Client) SoftwareVersion(ctx context.Context) (string, error) {
	if err := c.login(ctx); err != nil {
		return "", err
	}
	defer c.logout(ctx)

	b, status, err := c.do(ctx, http.MethodGet, "/system", nil, "")
	if err != nil {
		return "", fmt.Errorf("ribbon: SoftwareVersion: %w", err)
	}
	if status != http.StatusOK {
		return "", fmt.Errorf("ribbon: SoftwareVersion: HTTP %d: %.200s", status, b)
	}
	resp, _ := checkStatus(b)
	if resp.SWVersion != "" {
		return resp.SWVersion, nil
	}
	// Return raw body excerpt if XML parse didn't yield a version; let the caller
	// surface it rather than silently failing version reporting.
	return strings.TrimSpace(string(b[:min(len(b), 200)])), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
