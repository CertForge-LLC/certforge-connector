package connector

// appjob.go — App Connector cert delivery loop.
//
// Flow:
//   pending_csr    → generate RSA key + CSR; write key to key_path; POST CSR
//   pending_approval → wait (human approval in CertForge)
//   pending_acme   → wait (ACME issuance running on server)
//   cert_ready     → write full cert bundle to cert_path; write chain to chain_path (if set);
//                    run reload_cmd; mark done
//
// The private key is written to key_path during pending_csr so it survives connector
// restarts between CSR submission and cert delivery. The reload command is run only
// after cert_path is written, so the application always has a consistent key+cert pair.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/pkg/sftp"
)

// pollAppJobs fetches pending and cert_ready app connector jobs and executes them.
// Called on every poll tick alongside poll() for device jobs.
func (w *Worker) pollAppJobs(ctx context.Context) {
	if w.disabled || w.noAppJobs {
		return
	}
	jobs, err := w.client.ListAppJobs()
	if err != nil {
		// A 403 means this connector has no app-connector role (device-only connector).
		// Suppress subsequent polling rather than logging an error every 30 seconds.
		if strings.Contains(err.Error(), "403") {
			log.Printf("no app connector jobs for this agent — disabling app job polling")
			w.noAppJobs = true
			return
		}
		log.Printf("app job poll: %v", err)
		return
	}
	if len(jobs) == 0 {
		return
	}
	log.Printf("[app-connector] %d app job(s) to process", len(jobs))
	for _, j := range jobs {
		if err := w.executeAppJob(ctx, j); err != nil {
			log.Printf("[app-connector] job %s (%s): %v", j.ID, j.AppName, err)
			if markErr := w.client.MarkAppJobFailed(j.ID, err.Error()); markErr != nil {
				log.Printf("[app-connector] job %s: mark failed: %v", j.ID, markErr)
			}
		}
	}
}

func (w *Worker) executeAppJob(ctx context.Context, j AppJob) error {
	switch j.Status {
	case "pending_approval":
		log.Printf("[app-connector] job %s (%s): awaiting approval — waiting", j.ID, j.AppName)
		return nil
	case "pending_acme":
		log.Printf("[app-connector] job %s (%s): ACME in progress on server — waiting", j.ID, j.AppName)
		return nil
	case "pending_csr":
		return w.submitAppCSR(ctx, j)
	case "cert_ready":
		if j.Certificate == "" {
			return fmt.Errorf("cert_ready but certificate is empty — server-side bug")
		}
		return w.deliverAppCert(ctx, j)
	case "pending_query":
		return w.queryAppCert(ctx, j)
	case "pending_tls_probe":
		return w.probeAppTLS(ctx, j)
	default:
		log.Printf("[app-connector] job %s: unexpected status %q — skipping", j.ID, j.Status)
		return nil
	}
}

// submitAppCSR generates a private key and CSR for the app and posts the CSR to CertForge.
// The private key is written to key_path immediately so it is available when cert_ready arrives,
// even if the connector restarts in between.
func (w *Worker) submitAppCSR(ctx context.Context, j AppJob) error {
	if j.Domain == "" {
		return fmt.Errorf("domain not set on app %q", j.AppName)
	}
	isRemote := j.DeliveryMode == "remote_file" || j.DeliveryMode == "windows_cert_store"
	if j.KeyPath == "" && !isRemote {
		return fmt.Errorf("key_path not configured for app %q", j.AppName)
	}
	if j.CertPath == "" && !isRemote {
		return fmt.Errorf("cert_path not configured for app %q", j.AppName)
	}

	// Build SAN list: always include the primary domain; add extra SANs without duplicates.
	sans := []string{j.Domain}
	for _, s := range j.SANs {
		if s = strings.TrimSpace(s); s != "" && s != j.Domain {
			sans = append(sans, s)
		}
	}

	log.Printf("[app-connector] job %s (%s): generating RSA 2048 key + CSR for %s",
		j.ID, j.AppName, strings.Join(sans, ", "))

	keyPEM, csrPEM, err := generateAppCSR(j.Domain, sans)
	if err != nil {
		return fmt.Errorf("generate key+CSR: %w", err)
	}

	// Write private key before submitting the CSR — this way, if the connector restarts
	// between submission and cert_ready, the key is already in place.
	// For remote delivery modes with no local key_path, stage the key in a temp file.
	keyDest := j.KeyPath
	if keyDest == "" {
		keyDest = remoteKeyStaging(j.AppID)
	}
	if err := writeFileAtomic(keyDest, []byte(keyPEM), 0600); err != nil {
		return fmt.Errorf("write private key to %s: %w", keyDest, err)
	}
	log.Printf("[app-connector] job %s: private key written to %s", j.ID, keyDest)

	status, err := w.client.SubmitAppCSR(j.ID, csrPEM)
	if err != nil {
		return fmt.Errorf("submit CSR: %w", err)
	}
	log.Printf("[app-connector] job %s (%s): CSR submitted — status: %s", j.ID, j.AppName, status)
	return nil
}

// deliverAppCert writes the issued cert bundle and optional chain file, runs the reload
// command, and marks the job done on the server.
func (w *Worker) deliverAppCert(ctx context.Context, j AppJob) error {
	switch j.DeliveryMode {
	case "remote_file":
		log.Printf("[app-connector] job %s (%s): cert_ready — remote_file delivery to %s:%s",
			j.ID, j.AppName, j.RemoteHost, j.RemoteCertPath)
		if err := deliverRemoteFile(j); err != nil {
			return err
		}
	case "windows_cert_store":
		log.Printf("[app-connector] job %s (%s): cert_ready — windows_cert_store delivery to %s",
			j.ID, j.AppName, j.RemoteHost)
		thumbprint, err := deliverWindowsCertStore(j)
		if err != nil {
			return err
		}
		if thumbprint != "" {
			log.Printf("[app-connector] job %s (%s): thumbprint: %s", j.ID, j.AppName, thumbprint)
		}
	default:
		// local_file (default)
		if err := w.deliverLocalFile(ctx, j); err != nil {
			return err
		}
	}

	if err := w.client.MarkAppJobDone(j.ID); err != nil {
		return fmt.Errorf("mark done: %w", err)
	}
	log.Printf("[app-connector] job %s (%s): complete", j.ID, j.AppName)
	return nil
}

// deliverLocalFile writes the cert bundle and chain to the local filesystem and
// runs the reload command. Used for local_file delivery mode.
func (w *Worker) deliverLocalFile(ctx context.Context, j AppJob) error {
	log.Printf("[app-connector] job %s (%s): cert_ready — delivering to %s", j.ID, j.AppName, j.CertPath)

	// When the CA generated the private key server-side (ACME flow), the server sends it
	// back in key_pem. Write it to key_path first so the key matches the issued cert.
	if j.KeyPEM != "" && j.KeyPath != "" {
		if err := writeFileAtomic(j.KeyPath, []byte(j.KeyPEM), 0600); err != nil {
			return fmt.Errorf("write server-provided key to %s: %w", j.KeyPath, err)
		}
		log.Printf("[app-connector] job %s: server-provided private key written to %s", j.ID, j.KeyPath)
	}

	// Verify the private key is in place before touching cert files.
	if j.KeyPath != "" {
		if _, err := os.Stat(j.KeyPath); os.IsNotExist(err) {
			return fmt.Errorf(
				"private key not found at %s — if this host was re-imaged, delete this app and re-add it to restart the key generation flow",
				j.KeyPath,
			)
		}
	}

	// cert_path receives the full PEM bundle (leaf + intermediates + root).
	if j.CertPath != "" {
		if err := writeFileAtomic(j.CertPath, []byte(j.Certificate), 0644); err != nil {
			return fmt.Errorf("write cert to %s: %w", j.CertPath, err)
		}
		log.Printf("[app-connector] job %s: cert bundle written to %s", j.ID, j.CertPath)
	}

	// chain_path (optional) receives only the intermediates + root, stripped of the leaf.
	if j.ChainPath != "" {
		chain := pemChain(j.Certificate)
		if chain != "" {
			if err := writeFileAtomic(j.ChainPath, []byte(chain), 0644); err != nil {
				return fmt.Errorf("write chain to %s: %w", j.ChainPath, err)
			}
			log.Printf("[app-connector] job %s: chain written to %s", j.ID, j.ChainPath)
		}
	}

	if j.ReloadCmd != "" {
		log.Printf("[app-connector] job %s: running reload: %s", j.ID, j.ReloadCmd)
		if out, err := runReloadCmd(j.ReloadCmd); err != nil {
			return fmt.Errorf("reload command %q failed: %w\noutput: %s", j.ReloadCmd, err, strings.TrimSpace(out))
		}
		log.Printf("[app-connector] job %s: reload complete", j.ID)
	}
	return nil
}

// queryAppCert reads the cert from its installed location, parses it, and reports
// the expiry and subject info back to CertForge. For remote delivery modes it reads
// via SSH; for local_file it reads the local cert_path.
func (w *Worker) queryAppCert(ctx context.Context, j AppJob) error {
	var certPEM []byte
	var readFrom string

	switch j.DeliveryMode {
	case "remote_file", "windows_cert_store":
		path := j.RemoteCertPath
		if path == "" {
			return fmt.Errorf("remote_cert_path not configured for app %q", j.AppName)
		}
		sshClient, err := dialSSH(j)
		if err != nil {
			return fmt.Errorf("SSH connect for query: %w", err)
		}
		defer sshClient.Close()
		sc, err := sftp.NewClient(sshClient)
		if err != nil {
			return fmt.Errorf("SFTP subsystem for query: %w", err)
		}
		defer sc.Close()
		f, err := sc.Open(path)
		if err != nil {
			return fmt.Errorf("open remote cert %s: %w", path, err)
		}
		certPEM, err = io.ReadAll(f)
		f.Close()
		if err != nil {
			return fmt.Errorf("read remote cert %s: %w", path, err)
		}
		readFrom = j.RemoteHost + ":" + path
	default:
		if j.CertPath == "" {
			return fmt.Errorf("cert_path not configured for app %q", j.AppName)
		}
		var err error
		certPEM, err = os.ReadFile(j.CertPath)
		if err != nil {
			return fmt.Errorf("read cert file %s: %w", j.CertPath, err)
		}
		readFrom = j.CertPath
	}

	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return fmt.Errorf("no certificate found in %s", readFrom)
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse certificate from %s: %w", readFrom, err)
	}
	sans := cert.DNSNames
	if len(sans) == 0 && cert.Subject.CommonName != "" {
		sans = []string{cert.Subject.CommonName}
	}
	log.Printf("[app-connector] query job %s (%s): cert expires %s, CN=%s, SANs=%v (read from %s)",
		j.ID, j.AppName, cert.NotAfter.Format("2006-01-02"), cert.Subject.CommonName, sans, readFrom)
	if err := w.client.ReportAppCert(j.ID, cert.NotAfter, cert.Subject.CommonName, sans); err != nil {
		return fmt.Errorf("report cert: %w", err)
	}
	return nil
}

// probeAppTLS connects to the app's local TLS endpoint, reports the negotiated
// protocol version and cert serial back to CertForge, and checks whether the
// server accepts legacy TLS 1.0/1.1.
func (w *Worker) probeAppTLS(ctx context.Context, j AppJob) error {
	host := j.TLSProbeHost
	if host == "" {
		host = j.Domain
	}
	port := j.TLSProbePort
	if port == "" {
		port = "443"
	}
	addr := net.JoinHostPort(host, port)

	log.Printf("[app-connector] tls probe job %s (%s): probing %s", j.ID, j.AppName, addr)

	result := TLSProbeResult{}

	// Primary probe — capture TLS version, cipher suite, and leaf cert serial.
	dialCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	conn, err := (&tls.Dialer{
		NetDialer: &net.Dialer{},
		Config:    &tls.Config{InsecureSkipVerify: true, ServerName: host}, //nolint:gosec
	}).DialContext(dialCtx, "tcp", addr)
	if err != nil {
		result.Error = err.Error()
		log.Printf("[app-connector] tls probe job %s (%s): connect failed: %v", j.ID, j.AppName, err)
		if reportErr := w.client.ReportTLSProbe(j.ID, result); reportErr != nil {
			log.Printf("[app-connector] tls probe job %s: report: %v", j.ID, reportErr)
		}
		return nil // not a job failure — server records the probe error
	}
	state := conn.(*tls.Conn).ConnectionState()
	conn.Close()

	result.TLSVersion = int(state.Version)
	result.CipherSuite = int(state.CipherSuite)
	if len(state.PeerCertificates) > 0 {
		result.CertSerial = state.PeerCertificates[0].SerialNumber.String()
		if j.TLSExpectedSerial != "" {
			result.SerialMatch = result.CertSerial == j.TLSExpectedSerial
		}
	}

	// Secondary probe — test whether the server accepts TLS 1.1 or lower.
	oldCtx, oldCancel := context.WithTimeout(ctx, 10*time.Second)
	defer oldCancel()
	oldConn, oldErr := (&tls.Dialer{
		NetDialer: &net.Dialer{},
		Config: &tls.Config{ //nolint:gosec
			InsecureSkipVerify: true,
			ServerName:         host,
			MaxVersion:         tls.VersionTLS11,
		},
	}).DialContext(oldCtx, "tcp", addr)
	if oldErr == nil {
		oldConn.Close()
		result.AcceptsOldTLS = true
	}

	log.Printf("[app-connector] tls probe job %s (%s): tls=%d serial_match=%v accepts_old=%v",
		j.ID, j.AppName, result.TLSVersion, result.SerialMatch, result.AcceptsOldTLS)

	if err := w.client.ReportTLSProbe(j.ID, result); err != nil {
		return fmt.Errorf("report tls probe: %w", err)
	}
	return nil
}

// ── helpers ───────────────────────────────────────────────────────────────────

// generateAppCSR creates a 2048-bit RSA key and a CSR for the given CN and SAN list.
// Both key and CSR are returned as PEM strings.
func generateAppCSR(cn string, sans []string) (keyPEM, csrPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate RSA key: %w", err)
	}
	tmpl := &x509.CertificateRequest{
		Subject:  pkix.Name{CommonName: cn},
		DNSNames: sans,
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", "", fmt.Errorf("create CSR: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshal private key: %w", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	return keyPEM, csrPEM, nil
}

// writeFileAtomic writes data to path atomically by staging to a temp file and
// then renaming. Creates parent directories as needed with 0755 permissions.
func writeFileAtomic(path string, data []byte, mode os.FileMode) error {
	if err := os.MkdirAll(filepath.Dir(path), 0755); err != nil {
		return fmt.Errorf("create parent dir for %s: %w", path, err)
	}
	tmp := path + ".certforge.tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// runReloadCmd executes a shell command via sh -c and returns combined stdout+stderr.
func runReloadCmd(cmd string) (string, error) {
	c := exec.Command("sh", "-c", cmd)
	out, err := c.CombinedOutput()
	return string(out), err
}
