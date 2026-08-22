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
	"encoding/pem"
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

	hc        *http.Client
	cookieHdr string // "Cookie:" header value — all session cookies joined with "; "
	csrfToken string // csrfp_token value, sent as X-CSRF-Token on every request

	// pendingCert holds the server cert PEM waiting to be installed after the CA
	// chain is trusted. Ribbon validates the chain on import, so the CA cert (slot 2)
	// must be installed before the server cert (slot 1). The connector worker calls
	// InstallCert first then InstallTrustedRoot, so we defer the server cert install.
	pendingCert string
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
	// Ribbon sets two cookies: PHPSESSID (session) and csrfp_token (CSRF protection).
	// Both must be sent on every subsequent request, and csrfp_token must also be
	// sent as an X-CSRF-Token header for the device to accept any API call.
	var parts []string
	for _, ck := range resp.Cookies() {
		parts = append(parts, ck.Name+"="+ck.Value)
		if ck.Name == "csrfp_token" {
			c.csrfToken = ck.Value
		}
	}
	if len(parts) == 0 {
		return fmt.Errorf("ribbon: login: no session cookie in response")
	}
	c.cookieHdr = strings.Join(parts, "; ")
	return nil
}

func (c *Client) logout(ctx context.Context) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base()+"/logout", nil)
	if err == nil {
		req.Header.Set("Cookie", c.cookieHdr)
		if c.csrfToken != "" {
			req.Header.Set("X-CSRF-Token", c.csrfToken)
		}
		resp, err := c.httpClient().Do(req)
		if err == nil {
			resp.Body.Close()
		}
	}
	c.cookieHdr = ""
	c.csrfToken = ""
}

// do sends an authenticated request and returns the raw body.
func (c *Client) do(ctx context.Context, method, path string, body io.Reader, contentType string) ([]byte, int, error) {
	req, err := http.NewRequestWithContext(ctx, method, c.base()+path, body)
	if err != nil {
		return nil, 0, err
	}
	req.Header.Set("Cookie", c.cookieHdr)
	// Ribbon enforces CSRF protection — every request must carry the csrfp_token
	// both as a cookie (included above) and as the X-CSRF-Token header.
	if c.csrfToken != "" {
		req.Header.Set("X-CSRF-Token", c.csrfToken)
	}
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
//
// Observed envelope shape (app_status_entry carries a code attribute, no description child):
//
//	<root><status><http_code>NNN</http_code>
//	  <app_status href="..."><app_status_entry code="NNNNN" params=""/></app_status>
//	</status></root>
type ribbonAppEntry struct {
	Code string `xml:"code,attr"`
}
type ribbonResponse struct {
	HTTPCode   int            `xml:"status>http_code"`
	AppEntry   ribbonAppEntry `xml:"status>app_status>app_status_entry"`
	// CSR resource
	CSRContent string `xml:"csr>csrContent"`
	// System resource (firmware version) — Ribbon SWE-lite reports version at
	// rt_Software_Base_Version, e.g. "13.1.0", with build at rt_Software_Base_BuildNumber.
	SWVersion  string `xml:"system>rt_Software_Base_Version"`
	SWBuildNum string `xml:"system>rt_Software_Base_BuildNumber"`
}

// checkStatus returns a non-nil error if the device reported an application-level failure.
// On error, includes the app_status_entry code and the raw body (first 400 bytes) so
// the caller's log line shows the full Ribbon error for debugging.
//
// Ribbon returns HTTP 200 for some application-level failures (e.g. duplicate cert serial
// 15017, ECDSA key extraction error 15017). The real error sits in the XML
// app_status_entry code attribute. Code "0" or empty means success; any other value is
// an application error that the HTTP status code alone cannot detect.
func checkStatus(b []byte) (*ribbonResponse, error) {
	var r ribbonResponse
	if err := xml.Unmarshal(b, &r); err != nil {
		// Not all responses are well-formed XML (e.g. 204 No Content) — ignore parse errors
		// and let the HTTP status code be the authority.
		return &r, nil
	}
	if r.HTTPCode != 0 && r.HTTPCode != http.StatusOK {
		detail := r.AppEntry.Code
		if detail == "" {
			detail = strings.TrimSpace(string(b[:min(len(b), 400)]))
		}
		return &r, fmt.Errorf("device status %d: %s", r.HTTPCode, detail)
	}
	// Also check the embedded application status code for HTTP-200 failures.
	if code := r.AppEntry.Code; code != "" && code != "0" {
		detail := strings.TrimSpace(string(b[:min(len(b), 400)]))
		return &r, fmt.Errorf("device app error %s: %s", code, detail)
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

// InstallCert caches the full certificate chain for deferred installation.
// Ribbon validates the chain on import; sending the full bundle (leaf + intermediates)
// to slot 1 lets Ribbon verify the chain against its built-in root store rather than
// requiring every intermediate to be pre-loaded in the trusted CA slots.
// The actual push to slot 1 is deferred until InstallTrustedRoot has run (so the
// trusted CA slots are populated as a belt-and-suspenders fallback).
// Implements device.Device.
func (c *Client) InstallCert(_ context.Context, certPEM string) error {
	// Cache the full chain (leaf + intermediates). Sending the chain to slot 1
	// lets Ribbon anchor verification against its built-in firmware root store
	// (ISRG Root X1 etc.) without requiring the root to be in the trusted CA slots.
	c.pendingCert = strings.TrimSpace(certPEM)
	log.Printf("[ribbon] server cert chain cached on %s — will install after CA roots are loaded", c.Host)
	return nil
}

// installServerCert pushes the cached server cert PEM to certificate slot 1.
// It first tries the full chain bundle (leaf + intermediates); if the device
// returns 15020 (chain verification failed — typically because an anchor root
// is in the trust store but the ECDSA cross-sign path can't be followed), it
// retries with just the leaf cert. When the intermediate and root are already
// loaded into slots 2+ the device can verify the leaf alone.
func (c *Client) installServerCert(ctx context.Context) error {
	if err := c.doInstallServerCert(ctx, c.pendingCert, "server.pem"); err != nil {
		// 15020 = X509_V_ERR_UNABLE_TO_GET_ISSUER_CERT — the bundled chain can't
		// be anchored (often an ECDSA cross-sign the device firmware doesn't follow).
		// Retry with just the leaf cert; if the intermediate and root are already in
		// the trusted-CA slots the device can complete verification without the chain.
		if strings.Contains(err.Error(), "15020") {
			log.Printf("[ribbon] server cert chain verify failed (15020) on %s — retrying with leaf-only PEM", c.Host)
			leaf := extractLeafPEM(c.pendingCert)
			if leaf != "" {
				if err2 := c.doInstallServerCert(ctx, leaf, "server-leaf.pem"); err2 == nil {
					log.Printf("[ribbon] certificate installed on %s (leaf-only fallback)", c.Host)
					c.pendingCert = ""
					return nil
				}
			}
		}
		return err
	}
	log.Printf("[ribbon] certificate installed on %s", c.Host)
	c.pendingCert = ""
	return nil
}

func (c *Client) doInstallServerCert(ctx context.Context, certPEM, filename string) error {
	vals := url.Values{
		"CertFileOperation": {"1"}, // certOperationCopyAndPaste
		"CertFileContent":   {certPEM},
		"CertFileName":      {filename},
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
	return nil
}

// extractLeafPEM returns the first PEM block from a certificate bundle (the leaf cert).
func extractLeafPEM(bundle string) string {
	block, _ := pem.Decode([]byte(strings.TrimSpace(bundle)))
	if block == nil {
		return ""
	}
	return strings.TrimSpace(string(pem.EncodeToMemory(block)))
}

// InstallTrustedRoot uploads the CA chain into the device trust store (slots 2, 3, …),
// one cert per slot, then installs the deferred server cert to slot 1. Installing each
// cert individually is required because Ribbon's import endpoint accepts only one PEM
// block per call — a multi-cert bundle silently drops everything after the first.
//
// Certs that the device rejects (e.g. ECDSA intermediates on firmware that only
// supports RSA in the trust store) are logged and skipped rather than aborting the
// install, so the remaining chain certs and the hardcoded anchor certs can still land.
//
// After the chain loop, installAnchorCerts always attempts to install ISRG Root X1.
// Ribbon firmware 13.x does not include it in its built-in trust store, and the
// web UI rejects self-signed CA imports (X509 Verify Error 1), but the REST API
// /certificate/:id?action=import bypasses that UI-level check and accepts it.
// With ISRG Root X1 in a trusted CA slot and the full chain (leaf + intermediates +
// cross-sign) embedded in slot 1, Ribbon can anchor the trust path to the known root.
//
// POST /rest/certificate/N?action=import for N=2,3,… (CA certs)
// POST /rest/certificate/1?action=import (server cert)
// Implements device.TrustedRootInstaller — called automatically by the connector
// worker after InstallCert when the signing CA chain is available.
func (c *Client) InstallTrustedRoot(ctx context.Context, caPEM string) error {
	if err := c.login(ctx); err != nil {
		return err
	}
	defer c.logout(ctx)

	// Step 1: install each CA cert individually into consecutive trusted-CA slots.
	// Ribbon only imports one PEM block per POST; a bundle would silently discard
	// every cert after the first, leaving the chain incomplete.
	// Certs that fail (ECDSA not supported, duplicate serial) are skipped — errors
	// are non-fatal here because the anchor cert install below may complete the chain.
	slot := 2
	rest := []byte(strings.TrimSpace(caPEM))
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		certPEM := strings.TrimSpace(string(pem.EncodeToMemory(block)))
		vals := url.Values{
			"CertFileOperation": {"1"}, // certOperationCopyAndPaste
			"CertFileContent":   {certPEM},
			"CertFileName":      {fmt.Sprintf("ca-cert-%d.pem", slot)},
		}
		b, status, err := c.do(ctx, http.MethodPost,
			fmt.Sprintf("/certificate/%d?action=import", slot),
			strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded")
		if err != nil {
			log.Printf("[ribbon] trusted CA cert slot %d: network error: %v — skipping", slot, err)
			slot++
			continue
		}
		if status != http.StatusOK && status != http.StatusNoContent {
			log.Printf("[ribbon] trusted CA cert slot %d: HTTP %d — skipping", slot, status)
			slot++
			continue
		}
		if _, err := checkStatus(b); err != nil {
			// 15017 = duplicate serial or ECDSA cert rejected by this firmware;
			// log but continue so the anchor cert can still be installed.
			log.Printf("[ribbon] trusted CA cert slot %d: %v — skipping (ECDSA or duplicate?)", slot, err)
			slot++
			continue
		}
		log.Printf("[ribbon] trusted CA cert installed in slot %d on %s", slot, c.Host)
		slot++
	}

	// Step 2: install hardcoded CA anchors that the chain requires but firmware
	// does not include. Non-fatal — each anchor is attempted independently.
	c.installAnchorCerts(ctx, slot)

	log.Printf("[ribbon] trusted CA chain installed on %s (%d cert(s) attempted)", c.Host, slot-2)

	// Step 3: now that all CA certs are in place, flush the pending server cert to slot 1.
	if c.pendingCert != "" {
		if err := c.installServerCert(ctx); err != nil {
			return err
		}
	}
	return nil
}

// installAnchorCerts installs well-known CA root certificates that Ribbon firmware may
// not include in its built-in trust store. Each cert is attempted independently; a cert
// that is already installed (duplicate serial 15017) or otherwise rejected is logged and
// skipped without aborting the sequence.
//
// Why the REST API works when the web UI doesn't: Ribbon's PHP web UI validates imported
// trusted-CA certs with an extra X509 verification step against the current trust chain
// before persisting them. Self-signed roots (ISRG Root X1) have no issuer in the chain,
// so the UI rejects them with X509 Verify Error 1. The REST endpoint /certificate/:id
// ?action=import does not apply that pre-store check and accepts RSA roots directly.
func (c *Client) installAnchorCerts(ctx context.Context, startSlot int) {
	type anchor struct {
		name string
		pem  string
	}
	anchors := []anchor{
		{"ISRG Root X1", isrgRootX1PEM},
	}
	slot := startSlot
	for _, a := range anchors {
		vals := url.Values{
			"CertFileOperation": {"1"},
			"CertFileContent":   {strings.TrimSpace(a.pem)},
			"CertFileName":      {fmt.Sprintf("anchor-%d.pem", slot)},
		}
		b, status, err := c.do(ctx, http.MethodPost,
			fmt.Sprintf("/certificate/%d?action=import", slot),
			strings.NewReader(vals.Encode()), "application/x-www-form-urlencoded")
		if err != nil {
			log.Printf("[ribbon] anchor cert %q slot %d on %s: %v", a.name, slot, c.Host, err)
			slot++
			continue
		}
		if status != http.StatusOK && status != http.StatusNoContent {
			log.Printf("[ribbon] anchor cert %q slot %d on %s: HTTP %d: %s", a.name, slot, c.Host, status, b)
			slot++
			continue
		}
		if _, err := checkStatus(b); err != nil {
			log.Printf("[ribbon] anchor cert %q slot %d on %s: %v", a.name, slot, c.Host, err)
			slot++
			continue
		}
		log.Printf("[ribbon] anchor cert %q installed in slot %d on %s", a.name, slot, c.Host)
		slot++
	}
}

// isrgRootX1PEM is the ISRG Root X1 certificate (RSA-4096, self-signed, expires 2035).
// Let's Encrypt's YR-series chain: leaf → YR2 (intermediate) → Root YR (ECDSA cross-sign,
// issued by ISRG Root X1) → ISRG Root X1. Ribbon firmware 13.x does not include ISRG
// Root X1 in its built-in trust store, so without it the chain terminates at Root YR
// whose issuer cannot be found, producing verify_err 2 / error 15020. Installing it
// via the REST API completes the anchor and allows the full chain to verify.
const isrgRootX1PEM = `-----BEGIN CERTIFICATE-----
MIIFazCCA1OgAwIBAgIRAIIQz7DSQONZRGPgu2OCiwAwDQYJKoZIhvcNAQELBQAw
TzELMAkGA1UEBhMCVVMxKTAnBgNVBAoTIEludGVybmV0IFNlY3VyaXR5IFJlc2Vh
cmNoIEdyb3VwMRUwEwYDVQQDEwxJU1JHIFJvb3QgWDEwHhcNMTUwNjA0MTEwNDM4
WhcNMzUwNjA0MTEwNDM4WjBPMQswCQYDVQQGEwJVUzEpMCcGA1UEChMgSW50ZXJu
ZXQgU2VjdXJpdHkgUmVzZWFyY2ggR3JvdXAxFTATBgNVBAMTDElTUkcgUm9vdCBY
MTCCAiIwDQYJKoZIhvcNAQEBBQADggIPADCCAgoBggIBAK3oJHP0FDfzm54rVygc
h77ct984kIxuPOZXoHj3dcKi/vVqbvYATyjb3miGbESTtrFj/RQSa78f0uoxmyF+
0TM8ukj13Xnfs7j/EvEhmkvBioZxaUpmZmyPfjxwv60pIgbz5MDmgK7iS4+3mX6U
A5/TR5d8mUgjU+g4rk8Kb4Mu0UlXjIB0ttov0DiNewNwIRt18jA8+o+u3dpjq+sW
T8KOEUt+zwvo/7V3LvSye0rgTBIlDHCNAymg4VMk7BPZ7hm/ELNKjD+Jo2FR3qyH
B5T0Y3HsLuJvW5iB4YlcNHlsdu87kGJ55tukmi8mxdAQ4Q7e2RCOFvu396j3x+UC
B5iPNgiV5+I3lg02dZ77DnKxHZu8A/lJBdiB3QW0KtZB6awBdpUKD9jf1b0SHzUv
KBds0pjBqAlkd25HN7rOrFleaJ1/ctaJxQZBKT5ZPt0m9STJEadao0xAH0ahmbWn
OlFuhjuefXKnEgV4We0+UXgVCwOPjdAvBbI+e0ocS3MFEvzG6uBQE3xDk3SzynTn
jh8BCNAw1FtxNrQHusEwMFxIt4I7mKZ9YIqioymCzLq9gwQbooMDQaHWBfEbwrbw
qHyGO0aoSCqI3Haadr8faqU9GY/rOPNk3sgrDQoo//fb4hVC1CLQJ13hef4Y53CI
rU7m2Ys6xt0nUW7/vGT1M0NPAgMBAAGjQjBAMA4GA1UdDwEB/wQEAwIBBjAPBgNV
HRMBAf8EBTADAQH/MB0GA1UdDgQWBBR5tFnme7bl5AFzgAiIyBpY9umbbjANBgkq
hkiG9w0BAQsFAAOCAgEAVR9YqbyyqFDQDLHYGmkgJykIrGF1XIpu+ILlaS/V9lZL
ubhzEFnTIZd+50xx+7LSYK05qAvqFyFWhfFQDlnrzuBZ6brJFe+GnY+EgPbk6ZGQ
3BebYhtF8GaV0nxvwuo77x/Py9auJ/GpsMiu/X1+mvoiBOv/2X/qkSsisRcOj/KK
NFtY2PwByVS5uCbMiogziUwthDyC3+6WVwW6LLv3xLfHTjuCvjHIInNzktHCgKQ5
ORAzI4JMPJ+GslWYHb4phowim57iaztXOoJwTdwJx4nLCgdNbOhdjsnvzqvHu7Ur
TkXWStAmzOVyyghqpZXjFaH3pO3JLF+l+/+sKAIuvtd7u+Nxe5AW0wdeRlN8NwdC
jNPElpzVmbUq4JUagEiuTDkHzsxHpFKVK7q4+63SM1N95R1NbdWhscdCb+ZAJzVc
oyi3B43njTOQ5yOf+1CceWxG1bQVs5ZufpsMljq4Ui0/1lvh+wjChP4kqKOJ2qxq
4RgqsahDYVvTH9w7jXbyLeiNdd8XM2w9U/t7y0Ff/9yi0GE44Za4rF2LN9d11TPA
mRGunUHBcnWEvgJBQl9nJEiU0Zsnvgc/ubhPgXRR4Xq37Z0j4r7g1SgEEzwxA57d
emyPxgcYxn/eR44/KJ4EBs+lVDR3veyJm+kXQ99b21/+jh5Xos1AnX5iItreGCc=
-----END CERTIFICATE-----`

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
	resp, err := checkStatus(b)
	if err != nil {
		return "", fmt.Errorf("ribbon: SoftwareVersion: %w", err)
	}
	if resp.SWVersion != "" {
		if resp.SWBuildNum != "" {
			return resp.SWVersion + " build " + resp.SWBuildNum, nil
		}
		return resp.SWVersion, nil
	}
	// Version field not present in response — return empty rather than raw XML noise.
	return "", nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
