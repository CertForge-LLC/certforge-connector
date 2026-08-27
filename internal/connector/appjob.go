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
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// pollAppJobs fetches pending and cert_ready app connector jobs and executes them.
// Called on every poll tick alongside poll() for device jobs.
func (w *Worker) pollAppJobs(ctx context.Context) {
	if w.disabled {
		return
	}
	jobs, err := w.client.ListAppJobs()
	if err != nil {
		log.Printf("[app-connector] list jobs: %v", err)
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
	if j.KeyPath == "" {
		return fmt.Errorf("key_path not configured for app %q", j.AppName)
	}
	if j.CertPath == "" {
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
	if err := writeFileAtomic(j.KeyPath, []byte(keyPEM), 0600); err != nil {
		return fmt.Errorf("write private key to %s: %w", j.KeyPath, err)
	}
	log.Printf("[app-connector] job %s: private key written to %s", j.ID, j.KeyPath)

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
	log.Printf("[app-connector] job %s (%s): cert_ready — delivering to %s", j.ID, j.AppName, j.CertPath)

	// When the CA generated the private key server-side (ACME flow), the server sends it
	// back in key_pem. Write it to key_path first — overwriting the locally-generated key —
	// so the key on disk matches the certificate the CA issued.
	if j.KeyPEM != "" && j.KeyPath != "" {
		if err := writeFileAtomic(j.KeyPath, []byte(j.KeyPEM), 0600); err != nil {
			return fmt.Errorf("write server-provided key to %s: %w", j.KeyPath, err)
		}
		log.Printf("[app-connector] job %s: server-provided private key written to %s", j.ID, j.KeyPath)
	}

	// Verify the private key is in place before touching cert files.
	// If the key is missing (e.g. the host was re-imaged), fail fast with a clear message.
	if j.KeyPath != "" {
		if _, err := os.Stat(j.KeyPath); os.IsNotExist(err) {
			return fmt.Errorf(
				"private key not found at %s — if this host was re-imaged, delete this app and re-add it to restart the key generation flow",
				j.KeyPath,
			)
		}
	}

	// cert_path receives the full PEM bundle (leaf + intermediates + root).
	// This is what nginx's ssl_certificate and most app TLS configs expect.
	if j.CertPath != "" {
		if err := writeFileAtomic(j.CertPath, []byte(j.Certificate), 0644); err != nil {
			return fmt.Errorf("write cert to %s: %w", j.CertPath, err)
		}
		log.Printf("[app-connector] job %s: cert bundle written to %s", j.ID, j.CertPath)
	}

	// chain_path (optional) receives only the intermediates + root, stripped of the leaf.
	// Useful for apps that configure the CA chain separately (e.g. stunnel, some Java keystores).
	if j.ChainPath != "" {
		chain := pemChain(j.Certificate) // strips the first block (leaf cert)
		if chain != "" {
			if err := writeFileAtomic(j.ChainPath, []byte(chain), 0644); err != nil {
				return fmt.Errorf("write chain to %s: %w", j.ChainPath, err)
			}
			log.Printf("[app-connector] job %s: chain written to %s", j.ID, j.ChainPath)
		}
	}

	// Run the reload command (via sh -c so it can contain pipes, &&, etc.)
	if j.ReloadCmd != "" {
		log.Printf("[app-connector] job %s: running reload: %s", j.ID, j.ReloadCmd)
		if out, err := runReloadCmd(j.ReloadCmd); err != nil {
			// Return full error so it lands in the job's error field and the UI shows it.
			return fmt.Errorf("reload command %q failed: %w\noutput: %s", j.ReloadCmd, err, strings.TrimSpace(out))
		}
		log.Printf("[app-connector] job %s: reload complete", j.ID)
	}

	if err := w.client.MarkAppJobDone(j.ID); err != nil {
		// Cert is delivered but server mark failed. Log and return error so the connector
		// retries on the next poll (cert_ready still set on server).
		return fmt.Errorf("mark done: %w", err)
	}
	log.Printf("[app-connector] job %s (%s): complete — cert delivered and service reloaded", j.ID, j.AppName)
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
