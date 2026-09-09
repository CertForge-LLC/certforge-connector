// Package watchguard provides an SSH-based driver for WatchGuard Firebox appliances.
//
// WatchGuard Fireware exposes a restricted management shell over SSH on port 4118.
// Certificates are installed by running the `import certificate <slot>` CLI command
// and pasting the base64-encoded certificate and private key bodies through stdin.
// There is no REST API for certificate management.
//
// Certificate lifecycle:
//  1. GenerateCSR — generates a placeholder local CSR. Because this driver also
//     implements PrivateKeyInstaller, the worker will override this CSR with an
//     externally-generated key+CSR (connector side, with DNS SANs) and persist
//     the key on the server across poll cycles.
//  2. CertForge signs the external CSR via policy evaluation.
//  3. InstallPrivateKey — caches the private key PEM in memory; the Firebox needs
//     both the cert and key in the same SSH import session.
//  4. InstallCert — opens an SSH session to the Firebox on port 4118, runs
//     `import certificate <slot>`, and pastes the cert and key bodies.
//
// TLSContext selects the certificate slot:
//
//	0 (default) → proxy-server     (HTTPS/TLS deep-packet inspection)
//	1           → web-server-https (Firebox management HTTPS certificate)
//	2           → vpn              (IKEv2 / Mobile VPN with SSL)
//
// The management SSH port defaults to 4118; set DeviceConfig.Port to override.
package watchguard

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"net"
	"strings"
	"time"

	"github.com/certforge/certforge-connector/internal/device"
	"golang.org/x/crypto/ssh"
)

const defaultSSHPort = 4118

// Client connects to a single WatchGuard Firebox via SSH.
type Client struct {
	Host       string
	Port       int  // SSH management port; defaults to 4118
	Username   string
	Password   string
	TLSContext int  // 0=proxy-server, 1=web-server-https, 2=vpn
	SkipVerify bool // reserved for future SSH host-key pinning; currently unused

	// pendingKeyPEM holds the private key from InstallPrivateKey until
	// InstallCert consumes it. Both are sent in a single SSH import session.
	pendingKeyPEM string
}

func (c *Client) sshPort() int {
	if c.Port > 0 {
		return c.Port
	}
	return defaultSSHPort
}

// slotName maps TLSContext (int) to the WatchGuard CLI certificate slot name.
func (c *Client) slotName() string {
	switch c.TLSContext {
	case 1:
		return "web-server-https"
	case 2:
		return "vpn"
	default:
		return "proxy-server"
	}
}

// sshRun opens an SSH session to the Firebox, writes input to stdin, closes
// stdin (EOF), waits for the shell to exit, and returns combined stdout+stderr.
func (c *Client) sshRun(ctx context.Context, input string) (string, error) {
	cfg := &ssh.ClientConfig{
		User: c.Username,
		Auth: []ssh.AuthMethod{ssh.Password(c.Password)},
		// WatchGuard Firebox SSH host keys are self-signed and rotated on firmware
		// upgrades; pinning is not practical without an enrollment step.
		// This driver runs on the management network behind the firewall itself.
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec
		Timeout:         30 * time.Second,
	}

	addr := net.JoinHostPort(c.Host, fmt.Sprintf("%d", c.sshPort()))

	// Respect context cancellation during dial.
	dialDone := make(chan struct{ conn *ssh.Client; err error }, 1)
	go func() {
		conn, err := ssh.Dial("tcp", addr, cfg)
		dialDone <- struct{ conn *ssh.Client; err error }{conn, err}
	}()
	select {
	case <-ctx.Done():
		return "", ctx.Err()
	case r := <-dialDone:
		if r.err != nil {
			return "", fmt.Errorf("watchguard: ssh dial %s: %w", addr, r.err)
		}
		defer r.conn.Close()
		return c.runSession(ctx, r.conn, input)
	}
}

func (c *Client) runSession(_ context.Context, conn *ssh.Client, input string) (string, error) {
	sess, err := conn.NewSession()
	if err != nil {
		return "", fmt.Errorf("watchguard: new session: %w", err)
	}
	defer sess.Close()

	// WatchGuard's restricted shell requires a PTY allocation.
	if err := sess.RequestPty("vt100", 40, 200, ssh.TerminalModes{
		ssh.ECHO:          0,
		ssh.TTY_OP_ISPEED: 38400,
		ssh.TTY_OP_OSPEED: 38400,
	}); err != nil {
		return "", fmt.Errorf("watchguard: request pty: %w", err)
	}

	stdin, err := sess.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("watchguard: stdin pipe: %w", err)
	}

	var out strings.Builder
	sess.Stdout = &out
	sess.Stderr = &out

	if err := sess.Shell(); err != nil {
		return "", fmt.Errorf("watchguard: start shell: %w", err)
	}

	if _, err := fmt.Fprint(stdin, input); err != nil {
		return "", fmt.Errorf("watchguard: write stdin: %w", err)
	}
	stdin.Close() // signals EOF — Firebox CLI finalises the import on EOF

	_ = sess.Wait()
	return out.String(), nil
}

// stripPEMHeaders removes -----BEGIN/END ...----- lines, returning only the
// base64-encoded body that the Firebox CLI expects after the import command.
func stripPEMHeaders(pemStr string) string {
	var lines []string
	for _, line := range strings.Split(strings.TrimSpace(pemStr), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "-----") {
			continue
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

// checkOutput scans the SSH session output for known Firebox error indicators.
func checkOutput(slot, out string) error {
	lower := strings.ToLower(out)
	for _, bad := range []string{"error", "failed", "invalid", "not found", "denied"} {
		if strings.Contains(lower, bad) {
			return fmt.Errorf("watchguard: import certificate %s: device reported: %s",
				slot, strings.TrimSpace(out))
		}
	}
	return nil
}

// --- CSRGenerator (device.CSRGenerator) ---

// GenerateCSR generates a placeholder ECDSA P-256 CSR locally. Because this
// driver also implements PrivateKeyInstaller, the worker replaces this CSR with
// an externally-generated key+CSR (with DNS SANs) and persists the key on the
// server — so the exact output of this call is not used for signing.
func (c *Client) GenerateCSR(ctx context.Context, subject device.CertSubject) (string, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return "", fmt.Errorf("watchguard: generate key: %w", err)
	}

	cn := subject.CN
	if cn == "" {
		cn = c.Host
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
		return "", fmt.Errorf("watchguard: create CSR: %w", err)
	}
	return string(pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csrDER,
	})), nil
}

// --- device.Device ---

// PullCSR satisfies device.Device but is never called when GenerateCSR is present.
func (c *Client) PullCSR(_ context.Context) (string, error) {
	return "", fmt.Errorf("watchguard: PullCSR not supported — WatchGuard has no CSR generation API; use GenerateCSR")
}

// --- PrivateKeyInstaller (device.PrivateKeyInstaller) ---

// InstallPrivateKey caches the PEM-encoded private key until InstallCert is
// called. The Firebox CLI accepts the cert and key together in a single SSH
// import session, so they are sent at the same time in InstallCert.
func (c *Client) InstallPrivateKey(_ context.Context, keyPEM string) error {
	c.pendingKeyPEM = keyPEM
	return nil
}

// --- InstallCert (device.Device) ---

// InstallCert pushes the signed certificate and the pending private key to the
// Firebox via SSH. The `import certificate <slot>` command reads the cert body
// first, then the key body, terminated by EOF (stdin close).
//
// InstallPrivateKey must be called before InstallCert.
func (c *Client) InstallCert(ctx context.Context, certPEM string) error {
	if c.pendingKeyPEM == "" {
		return fmt.Errorf("watchguard: InstallCert: no pending private key — InstallPrivateKey must be called first")
	}

	certBody := stripPEMHeaders(certPEM)
	keyBody := stripPEMHeaders(c.pendingKeyPEM)
	slot := c.slotName()

	// Format expected by Firebox CLI:
	//   import certificate <slot>\n
	//   <base64 cert body>\n
	//   <base64 key body>\n
	// Stdin close signals EOF and finalises the import.
	input := fmt.Sprintf("import certificate %s\n%s\n%s\n", slot, certBody, keyBody)

	out, err := c.sshRun(ctx, input)
	if err != nil {
		return err
	}
	if err := checkOutput(slot, out); err != nil {
		return err
	}

	c.pendingKeyPEM = "" // consumed
	return nil
}

// --- TrustedRootInstaller (device.TrustedRootInstaller) ---

// InstallTrustedRoot pushes a CA certificate chain to the Firebox trusted
// certificate store. This is needed when CertForge issues certs from an internal
// CA — the Firebox must trust the signing CA to validate its own certificate chain.
//
// NOTE: The exact WatchGuard CLI command for CA certificate import should be
// verified against your Fireware version. The slot name used here ("ca-cert")
// reflects the most common Fireware CLI form; it may differ on older firmware.
func (c *Client) InstallTrustedRoot(ctx context.Context, caPEM string) error {
	// Parse each cert in the chain and import them individually.
	// Firebox accepts one CA cert per import command.
	rest := []byte(strings.TrimSpace(caPEM))
	index := 0
	for len(rest) > 0 {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}

		certBody := string(pem.EncodeToMemory(block))
		certBody = stripPEMHeaders(certBody)

		// Firebox CA import — slot name may need adjustment per firmware version.
		// Verify with: SSH to Firebox → type `import certificate ?` to list slots.
		input := fmt.Sprintf("import certificate ca-cert\n%s\n", certBody)
		out, err := c.sshRun(ctx, input)
		if err != nil {
			return fmt.Errorf("watchguard: install trusted root [%d]: %w", index, err)
		}
		if err := checkOutput("ca-cert", out); err != nil {
			return fmt.Errorf("watchguard: install trusted root [%d]: %w", index, err)
		}
		index++
	}
	return nil
}
