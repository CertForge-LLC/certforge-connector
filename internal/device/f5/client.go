// Package f5 provides an iControl REST client for F5 BIG-IP devices.
// It targets the iControl REST API available on TMOS 11.6+.
//
// Certificate lifecycle flow:
//  1. Call PullCSR to generate a new CSR from the existing key of the target
//     client-ssl profile without disturbing the running configuration.
//     The working CSR object is deleted from the device after download.
//  2. CertForge signs the CSR via policy evaluation.
//  3. Call InstallCert to upload the signed leaf certificate and install it
//     under the same name, so the SSL profile picks it up automatically.
//  4. Call InstallTrustedRoot to push the signing chain (intermediates) and
//     wire it into the profile's chain field so TLS handshakes include the
//     full certificate chain.
//
// TLSContext selects which client-ssl profile to target (0-based index into
// the profile list returned by GET /mgmt/tm/ltm/profile/client-ssl).
// Check the correct index under Local Traffic → Profiles → SSL → Client in
// the BIG-IP UI, or call ListClientSSLProfiles during initial setup.
package f5

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/certforge/certforge-connector/internal/device"
)

const (
	csrWorkName       = "certforge-renewal" // working CSR object name on device; deleted after download
	chainWorkName     = "certforge-chain"   // chain cert object name on device; updated on each renewal
	managedCertName   = "certforge"         // cert object installed/updated by CertForge
	managedKeyName    = "certforge"         // key object installed/updated by CertForge
)

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

// upload sends raw bytes to the F5 file-transfer staging area.
// The iControl REST upload API requires a Content-Range header of the form
// "first-last/total" even for single-chunk (non-chunked) uploads — without it
// some TMOS versions reject the request with HTTP 400 or 411.
func (c *Client) upload(ctx context.Context, path string, data []byte) ([]byte, int, error) {
	url := c.base() + path
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(data))
	if err != nil {
		return nil, 0, err
	}
	req.SetBasicAuth(c.Username, c.Password)
	req.Header.Set("Content-Type", "application/octet-stream")
	if len(data) > 0 {
		req.Header.Set("Content-Range", fmt.Sprintf("0-%d/%d", len(data)-1, len(data)))
	}

	resp, err := c.httpClient().Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("f5: upload: %w", err)
	}
	defer resp.Body.Close()

	b, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return nil, resp.StatusCode, err
	}
	return b, resp.StatusCode, nil
}

// pemLeaf returns the first PEM block from a (potentially multi-cert) PEM string.
// BIG-IP's cert install endpoint expects a single certificate, not a chain.
func pemLeaf(fullPEM string) string {
	block, _ := pem.Decode([]byte(fullPEM))
	if block == nil {
		return fullPEM
	}
	return string(pem.EncodeToMemory(block))
}

// --- client-ssl profile lookup ---

type sslProfile struct {
	Name         string             `json:"name"`
	Partition    string             `json:"partition"`
	Cert         string             `json:"cert"`
	Key          string             `json:"key"`
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
	p := strings.TrimSpace(string(body))
	if !strings.HasPrefix(p, "-----BEGIN") {
		return "", fmt.Errorf("f5: download CSR: unexpected response (not PEM): %.200s", p)
	}
	return p, nil
}

// deleteCSR removes the named CSR object from the device's ssl-csr store.
// Called after a successful download to avoid stale objects accumulating on the BIG-IP.
// Not found (404) is treated as success — the object may have been cleaned up already.
func (c *Client) deleteCSR(ctx context.Context, partition, csrName string) error {
	path := fmt.Sprintf("/mgmt/tm/sys/file/ssl-csr/~%s~%s", partition, csrName)
	_, status, err := c.do(ctx, http.MethodDelete, path, nil, "")
	if err != nil {
		return err
	}
	if status != http.StatusOK && status != http.StatusNoContent && status != http.StatusNotFound {
		return fmt.Errorf("HTTP %d", status)
	}
	return nil
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
// client-ssl profile. The key never leaves the BIG-IP. The working CSR object
// is deleted from the device after a successful download.
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

	p, err := c.downloadCSR(ctx, partition, csrWorkName)
	if err != nil {
		return "", err
	}

	// Clean up — the working CSR is no longer needed on the device.
	_ = c.deleteCSR(ctx, partition, csrWorkName)

	return p, nil
}

// --- GenerateCSR implements device.CSRGenerator ---

// GenerateCSR tries to generate a CSR from the device's existing private key via
// iControl REST. On BIG-IP systems without an LTM licence the /sys/crypto/csr
// endpoint returns HTTP 403; in that case a local placeholder CSR is generated so
// the worker can continue. Because F5 also implements PrivateKeyInstaller the
// worker will override this CSR with an externally-generated key+CSR (connector
// side, with DNS SANs) and call InstallPrivateKey before InstallCert — so the
// exact CSR returned here is not used for signing.
func (c *Client) GenerateCSR(ctx context.Context, subject device.CertSubject) (string, error) {
	profile, err := c.targetProfile(ctx)
	if err != nil {
		return "", err
	}
	_, keyName, partition, err := certKeyNames(profile)
	if err != nil {
		return "", err
	}

	cn := subject.CN
	if cn == "" {
		cn = c.Host
	}

	// Attempt device-side CSR generation (reuses the existing private key on BIG-IP,
	// so the key never leaves the device). This requires an LTM licence.
	if csrErr := c.generateCSR(ctx, csrWorkName, partition, keyName, cn); csrErr == nil {
		p, dlErr := c.downloadCSR(ctx, partition, csrWorkName)
		if dlErr != nil {
			return "", dlErr
		}
		_ = c.deleteCSR(ctx, partition, csrWorkName)
		return p, nil
	}

	// Device-side generation failed (most likely HTTP 403 — licence required).
	// Fall back to a locally-generated placeholder CSR. The worker will replace
	// this with generateExternalCSR because F5 also implements PrivateKeyInstaller.
	key, keyErr := rsa.GenerateKey(rand.Reader, 2048)
	if keyErr != nil {
		return "", fmt.Errorf("f5: local CSR fallback: %w", keyErr)
	}
	subj := pkix.Name{CommonName: cn}
	if subject.O != "" {
		subj.Organization = []string{subject.O}
	}
	if subject.OU != "" {
		subj.OrganizationalUnit = []string{subject.OU}
	}
	if subject.L != "" {
		subj.Locality = []string{subject.L}
	}
	if subject.ST != "" {
		subj.Province = []string{subject.ST}
	}
	if subject.C != "" {
		subj.Country = []string{subject.C}
	}
	tmpl := &x509.CertificateRequest{Subject: subj, DNSNames: subject.SANs}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", fmt.Errorf("f5: local CSR fallback: create CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER})), nil
}

// --- InstallPrivateKey implements device.PrivateKeyInstaller ---

// InstallPrivateKey uploads a PEM-encoded private key to the BIG-IP and installs
// it as a new managed object named managedKeyName (/Common/certforge). Using a
// dedicated name avoids the access-denied error that occurs when trying to
// overwrite protected system keys such as /Common/default.key.
// InstallCert is responsible for patching the client-ssl profile to reference
// the new key after the cert is installed.
func (c *Client) InstallPrivateKey(ctx context.Context, keyPEM string) error {
	profile, err := c.targetProfile(ctx)
	if err != nil {
		return err
	}
	_, _, partition, err := certKeyNames(profile)
	if err != nil {
		return err
	}

	fileName := managedKeyName + ".key"
	uploadBody, uploadStatus, err := c.upload(ctx,
		"/mgmt/shared/file-transfer/uploads/"+fileName,
		[]byte(keyPEM))
	if err != nil {
		return fmt.Errorf("f5: upload key: %w", err)
	}
	if uploadStatus != http.StatusOK && uploadStatus != http.StatusNoContent {
		return fmt.Errorf("f5: upload key: HTTP %d: %s", uploadStatus, uploadBody)
	}

	installBody, installStatus, err := c.postJSON(ctx, "/mgmt/tm/sys/crypto/key", map[string]string{
		"command":         "install",
		"name":            fmt.Sprintf("/%s/%s", partition, managedKeyName),
		"from-local-file": fmt.Sprintf("/var/config/rest/downloads/%s", fileName),
	})
	if err != nil {
		return fmt.Errorf("f5: install key: %w", err)
	}
	if installStatus != http.StatusOK && installStatus != http.StatusCreated {
		return fmt.Errorf("f5: install key: HTTP %d: %s", installStatus, installBody)
	}
	return nil
}

// --- InstallCert implements device.Device ---

// InstallCert uploads the signed leaf certificate to the BIG-IP and installs it
// as a new managed object named managedCertName (/Common/certforge). After the cert
// is installed, it patches the client-ssl profile to reference both the new cert and
// the new key (installed earlier by InstallPrivateKey), so the profile is wired to
// the CertForge-managed objects without touching protected system files.
// Only the leaf cert is sent here; the signing chain is handled by InstallTrustedRoot.
func (c *Client) InstallCert(ctx context.Context, certPEM string) error {
	profile, err := c.targetProfile(ctx)
	if err != nil {
		return err
	}

	_, _, partition, err := certKeyNames(profile)
	if err != nil {
		return err
	}

	// BIG-IP's cert install endpoint expects a single certificate — extract the leaf.
	fileName := managedCertName + ".crt"
	uploadBody, uploadStatus, err := c.upload(ctx,
		"/mgmt/shared/file-transfer/uploads/"+fileName,
		[]byte(pemLeaf(certPEM)))
	if err != nil {
		return fmt.Errorf("f5: upload cert: %w", err)
	}
	if uploadStatus != http.StatusOK && uploadStatus != http.StatusNoContent {
		return fmt.Errorf("f5: upload cert: HTTP %d: %s", uploadStatus, uploadBody)
	}

	// Install the uploaded cert under the managed cert name.
	installBody, installStatus, err := c.postJSON(ctx, "/mgmt/tm/sys/crypto/cert", map[string]string{
		"command":         "install",
		"name":            fmt.Sprintf("/%s/%s", partition, managedCertName),
		"from-local-file": fmt.Sprintf("/var/config/rest/downloads/%s", fileName),
	})
	if err != nil {
		return fmt.Errorf("f5: install cert: %w", err)
	}
	if installStatus != http.StatusOK && installStatus != http.StatusCreated {
		return fmt.Errorf("f5: install cert: HTTP %d: %s", installStatus, installBody)
	}

	// Patch the client-ssl profile to reference the new managed cert and key.
	// This wires the profile away from the old (possibly write-protected) system objects.
	// BIG-IP crypto objects are stored without file extensions in the API — the install
	// command uses name=/Common/certforge, so the object is /Common/certforge (not .crt/.key).
	certRef := fmt.Sprintf("/%s/%s", partition, managedCertName)
	keyRef := fmt.Sprintf("/%s/%s", partition, managedKeyName)
	profilePath := fmt.Sprintf("/mgmt/tm/ltm/profile/client-ssl/~%s~%s", partition, profile.Name)
	patchData, _ := json.Marshal(map[string]string{
		"cert": certRef,
		"key":  keyRef,
	})
	patchBody, patchStatus, err := c.do(ctx, http.MethodPatch, profilePath,
		bytes.NewReader(patchData), "application/json")
	if err != nil {
		return fmt.Errorf("f5: patch profile cert/key: %w", err)
	}
	if patchStatus != http.StatusOK {
		return fmt.Errorf("f5: patch profile cert/key: HTTP %d: %s", patchStatus, patchBody)
	}
	return nil
}

// --- InstallTrustedRoot implements device.TrustedRootInstaller ---

// InstallTrustedRoot uploads the signing chain (intermediate + root CA PEMs)
// to the BIG-IP and wires it into the target client-ssl profile's chain field
// so that TLS handshakes include the full certificate chain. Without this,
// clients that don't have the intermediate cached will see "Not secure".
//
// The chain cert is stored as a persistent object named certforge-chain on the
// device and is overwritten on each renewal.
func (c *Client) InstallTrustedRoot(ctx context.Context, caPEM string) error {
	profile, err := c.targetProfile(ctx)
	if err != nil {
		return err
	}
	_, _, partition, err := certKeyNames(profile)
	if err != nil {
		return err
	}

	// Upload chain PEM to staging area.
	fileName := chainWorkName + ".crt"
	uploadBody, uploadStatus, err := c.upload(ctx,
		"/mgmt/shared/file-transfer/uploads/"+fileName,
		[]byte(caPEM))
	if err != nil {
		return fmt.Errorf("f5: upload chain: %w", err)
	}
	if uploadStatus != http.StatusOK && uploadStatus != http.StatusNoContent {
		return fmt.Errorf("f5: upload chain: HTTP %d: %s", uploadStatus, uploadBody)
	}

	// Install as a named cert object (overwrites any previous certforge-chain).
	installBody, installStatus, err := c.postJSON(ctx, "/mgmt/tm/sys/crypto/cert", map[string]string{
		"command":         "install",
		"name":            fmt.Sprintf("/%s/%s", partition, chainWorkName),
		"from-local-file": fmt.Sprintf("/var/config/rest/downloads/%s", fileName),
	})
	if err != nil {
		return fmt.Errorf("f5: install chain cert: %w", err)
	}
	if installStatus != http.StatusOK && installStatus != http.StatusCreated {
		return fmt.Errorf("f5: install chain cert: HTTP %d: %s", installStatus, installBody)
	}

	// Wire the chain into the client-ssl profile so BIG-IP sends it during handshakes.
	// The chain field takes the full F5 path: /Partition/name.crt
	chainRef := fmt.Sprintf("/%s/%s.crt", partition, chainWorkName)
	patchData, _ := json.Marshal(map[string]string{"chain": chainRef})
	profilePath := fmt.Sprintf("/mgmt/tm/ltm/profile/client-ssl/~%s~%s", partition, profile.Name)
	patchBody, patchStatus, err := c.do(ctx, http.MethodPatch, profilePath,
		bytes.NewReader(patchData), "application/json")
	if err != nil {
		return fmt.Errorf("f5: update profile chain: %w", err)
	}
	if patchStatus != http.StatusOK {
		return fmt.Errorf("f5: update profile chain: HTTP %d: %s", patchStatus, patchBody)
	}
	return nil
}

// Ping verifies connectivity and credentials by listing client-ssl profiles.
func (c *Client) Ping(ctx context.Context) error {
	_, err := c.ListClientSSLProfiles(ctx)
	return err
}
