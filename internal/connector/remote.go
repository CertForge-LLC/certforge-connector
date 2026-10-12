package connector

// remote.go — SSH/SFTP delivery for remote_file and windows_cert_store modes.
//
// remote_file:         SSH dial → SFTP put cert+key → SSH exec reload_cmd
// windows_cert_store:  SSH dial → SFTP put PFX → SSH exec rendered PS template

import (
	"bytes"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/pkg/sftp"
	"golang.org/x/crypto/ssh"
	"software.sslmate.com/src/go-pkcs12"
)

// remoteKeyStaging returns the local staging path for the private key when
// no explicit key_path is configured (remote delivery modes).
// Both submitAppCSR and deliverAppCert derive the same path from app_id.
func remoteKeyStaging(appID string) string {
	return filepath.Join(os.TempDir(), "certforge-key-"+appID+".pem")
}

// deliverRemoteFile delivers a cert/key to a remote host via SSH/SFTP and
// optionally runs a reload command on the remote host.
func deliverRemoteFile(j AppJob) error {
	sshClient, err := dialSSH(j)
	if err != nil {
		return fmt.Errorf("SSH connect to %s: %w", j.RemoteHost, err)
	}
	defer sshClient.Close()

	sc, err := sftp.NewClient(sshClient)
	if err != nil {
		return fmt.Errorf("SFTP subsystem: %w", err)
	}
	defer sc.Close()

	keyPEM := resolveKeyPEM(j)

	if j.RemoteCertPath != "" {
		if err := sftpPut(sc, []byte(j.Certificate), j.RemoteCertPath, 0644); err != nil {
			return fmt.Errorf("SFTP put cert to %s: %w", j.RemoteCertPath, err)
		}
		log.Printf("[remote-delivery] job %s: cert written to %s:%s", j.ID, j.RemoteHost, j.RemoteCertPath)
	}

	if j.RemoteKeyPath != "" && keyPEM != "" {
		if err := sftpPut(sc, []byte(keyPEM), j.RemoteKeyPath, 0600); err != nil {
			return fmt.Errorf("SFTP put key to %s: %w", j.RemoteKeyPath, err)
		}
		log.Printf("[remote-delivery] job %s: key written to %s:%s", j.ID, j.RemoteHost, j.RemoteKeyPath)
	}

	if j.ReloadCmd != "" {
		log.Printf("[remote-delivery] job %s: running remote reload: %s", j.ID, j.ReloadCmd)
		out, err := sshRun(sshClient, j.ReloadCmd)
		if err != nil {
			return fmt.Errorf("remote reload %q failed: %w\noutput: %s", j.ReloadCmd, err, strings.TrimSpace(out))
		}
	}
	return nil
}

// deliverWindowsCertStore imports a PFX into the Windows Certificate Store on a
// remote host via SSH. It renders the PowerShell template with job variables,
// execs it over SSH, and parses the thumbprint from stdout.
// Returns the certificate thumbprint on success.
func deliverWindowsCertStore(j AppJob) (string, error) {
	sshClient, err := dialSSH(j)
	if err != nil {
		return "", fmt.Errorf("SSH connect to %s: %w", j.RemoteHost, err)
	}
	defer sshClient.Close()

	sc, err := sftp.NewClient(sshClient)
	if err != nil {
		return "", fmt.Errorf("SFTP subsystem: %w", err)
	}
	defer sc.Close()

	pfxData, notAfter, err := buildPFX(j)
	if err != nil {
		return "", fmt.Errorf("build PFX: %w", err)
	}

	pfxPath := j.RemoteCertPath
	if pfxPath == "" {
		pfxPath = `C:\Windows\Temp\cf_` + j.ID[:8] + `.pfx`
	}
	if err := sftpPut(sc, pfxData, pfxPath, 0600); err != nil {
		return "", fmt.Errorf("SFTP put PFX to %s: %w", pfxPath, err)
	}
	log.Printf("[remote-delivery] job %s: PFX written to %s:%s", j.ID, j.RemoteHost, pfxPath)

	sans := strings.Join(j.SANs, ",")
	psScript, err := renderPSTemplate(j.PSTemplate, psTemplateVars{
		PFXPath:     pfxPath,
		PFXPassword: j.PFXPassword,
		CommonName:  j.Domain,
		SANs:        sans,
		NotAfter:    notAfter,
		JobID:       j.ID,
	})
	if err != nil {
		return "", fmt.Errorf("render PS template: %w", err)
	}

	// Run via powershell -EncodedCommand to avoid quoting issues.
	psCmd := buildPSCommand(psScript)
	log.Printf("[remote-delivery] job %s: executing PowerShell on %s", j.ID, j.RemoteHost)
	out, err := sshRun(sshClient, psCmd)
	if err != nil {
		return "", fmt.Errorf("PowerShell exec failed: %w\noutput: %s", err, strings.TrimSpace(out))
	}

	var thumbprint string
	for _, line := range strings.Split(out, "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "CF_THUMBPRINT:") {
			thumbprint = strings.TrimSpace(strings.TrimPrefix(line, "CF_THUMBPRINT:"))
		}
	}
	log.Printf("[remote-delivery] job %s: Windows cert store import complete, thumbprint=%q", j.ID, thumbprint)
	return thumbprint, nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

func dialSSH(j AppJob) (*ssh.Client, error) {
	if j.SSHKey == "" {
		return nil, fmt.Errorf("no SSH key configured for remote delivery")
	}
	signer, err := ssh.ParsePrivateKey([]byte(j.SSHKey))
	if err != nil {
		return nil, fmt.Errorf("parse SSH key: %w", err)
	}
	port := j.RemotePort
	if port == 0 {
		port = 22
	}
	addr := fmt.Sprintf("%s:%d", j.RemoteHost, port)
	cfg := &ssh.ClientConfig{
		User:            j.RemoteUser,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(signer)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), //nolint:gosec — host key pinning is a future iteration
		Timeout:         30 * time.Second,
	}
	return ssh.Dial("tcp", addr, cfg)
}

func sftpPut(sc *sftp.Client, data []byte, remotePath string, mode os.FileMode) error {
	dir := filepath.ToSlash(filepath.Dir(remotePath))
	if dir != "" && dir != "." {
		_ = sc.MkdirAll(dir)
	}
	f, err := sc.OpenFile(remotePath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := f.Chmod(mode); err != nil {
		// Non-fatal on Windows — chmod not always supported.
		log.Printf("[remote-delivery] chmod %s: %v (continuing)", remotePath, err)
	}
	_, err = io.Copy(f, bytes.NewReader(data))
	return err
}

func sshRun(client *ssh.Client, cmd string) (string, error) {
	sess, err := client.NewSession()
	if err != nil {
		return "", err
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(cmd)
	return string(out), err
}

// resolveKeyPEM returns the private key PEM for a job.
// Prefers j.KeyPEM (server-provided for ACME flows), then reads from j.KeyPath or
// the deterministic staging path for remote delivery modes.
func resolveKeyPEM(j AppJob) string {
	if j.KeyPEM != "" {
		return j.KeyPEM
	}
	path := j.KeyPath
	if path == "" {
		path = remoteKeyStaging(j.AppID)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		log.Printf("[remote-delivery] resolveKeyPEM: read %s: %v", path, err)
		return ""
	}
	return string(raw)
}

// buildPFX assembles a PKCS#12 archive from the job's cert chain and private key.
// Returns the PFX bytes and the leaf certificate's NotAfter.
func buildPFX(j AppJob) (pfxData []byte, notAfter time.Time, err error) {
	keyPEM := resolveKeyPEM(j)
	if keyPEM == "" {
		return nil, time.Time{}, fmt.Errorf("no private key available for PFX generation")
	}
	if j.Certificate == "" {
		return nil, time.Time{}, fmt.Errorf("certificate is empty")
	}

	// Parse private key — connector generates PKCS8 keys; also handle PKCS1 for flexibility.
	keyBlock, _ := pem.Decode([]byte(keyPEM))
	if keyBlock == nil {
		return nil, time.Time{}, fmt.Errorf("no PEM block found in private key")
	}
	var privateKey interface{}
	switch keyBlock.Type {
	case "PRIVATE KEY":
		privateKey, err = x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("parse PKCS8 private key: %w", err)
		}
	case "RSA PRIVATE KEY":
		privateKey, err = x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
		if err != nil {
			return nil, time.Time{}, fmt.Errorf("parse PKCS1 private key: %w", err)
		}
	default:
		return nil, time.Time{}, fmt.Errorf("unsupported private key PEM type: %s", keyBlock.Type)
	}

	// Parse cert chain: first block is leaf, rest are intermediates.
	var leafCert *x509.Certificate
	var caCerts []*x509.Certificate
	rest := []byte(j.Certificate)
	for {
		var block *pem.Block
		block, rest = pem.Decode(rest)
		if block == nil {
			break
		}
		if block.Type != "CERTIFICATE" {
			continue
		}
		cert, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, time.Time{}, fmt.Errorf("parse certificate: %w", parseErr)
		}
		if leafCert == nil {
			leafCert = cert
		} else {
			caCerts = append(caCerts, cert)
		}
	}
	if leafCert == nil {
		return nil, time.Time{}, fmt.Errorf("no certificate found in bundle")
	}

	pfxData, err = pkcs12.Modern.Encode(privateKey, leafCert, caCerts, j.PFXPassword)
	if err != nil {
		return nil, time.Time{}, fmt.Errorf("pkcs12 encode: %w", err)
	}
	return pfxData, leafCert.NotAfter, nil
}

type psTemplateVars struct {
	PFXPath     string
	PFXPassword string
	CommonName  string
	SANs        string
	NotAfter    time.Time
	JobID       string
}

func renderPSTemplate(tmplStr string, vars psTemplateVars) (string, error) {
	t, err := template.New("ps").Parse(tmplStr)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := t.Execute(&buf, vars); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// buildPSCommand wraps a PowerShell script in a -EncodedCommand invocation
// to avoid quoting and newline issues when exec'd over SSH.
func buildPSCommand(script string) string {
	// PowerShell -EncodedCommand takes UTF-16LE base64.
	utf16 := encodeUTF16LE(script)
	encoded := base64Encode(utf16)
	return "powershell -NonInteractive -EncodedCommand " + encoded
}

// encodeUTF16LE encodes s as a UTF-16 little-endian byte slice.
func encodeUTF16LE(s string) []byte {
	runes := []rune(s)
	b := make([]byte, len(runes)*2)
	for i, r := range runes {
		b[i*2] = byte(r)
		b[i*2+1] = byte(r >> 8)
	}
	return b
}

// base64Encode returns the standard base64 encoding of b.
func base64Encode(b []byte) string {
	const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/"
	var buf strings.Builder
	for i := 0; i < len(b); i += 3 {
		n := 3
		if i+n > len(b) {
			n = len(b) - i
		}
		var v uint32
		for j := 0; j < n; j++ {
			v |= uint32(b[i+j]) << (16 - uint(j)*8)
		}
		for j := 0; j < n+1; j++ {
			buf.WriteByte(alphabet[(v>>(18-uint(j)*6))&0x3F])
		}
		for j := n + 1; j < 4; j++ {
			buf.WriteByte('=')
		}
	}
	return buf.String()
}
