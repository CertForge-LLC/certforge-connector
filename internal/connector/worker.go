package connector

import (
	"context"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"log"
	"time"
)

// Worker polls CertForge for device jobs and executes them.
type Worker struct {
	cfg      *Config
	client   *Client
	version  string
	// localCAs maps ca_connector_id → LocalCA for governed local signing (DTP-validated).
	// Populated from private_cas[] entries (and private_ca if it has a ca_connector_id).
	localCAs map[string]*LocalCA
	// legacyCA is set when private_ca has no ca_connector_id (pre-governance behavior).
	// Signing still works but bypasses DTP validation — a warning is logged each use.
	legacyCA *LocalCA
}

func NewWorker(cfg *Config, version string) (*Worker, error) {
	w := &Worker{
		cfg:      cfg,
		client:   NewClient(cfg.CertForgeURL, cfg.APIKey),
		version:  version,
		localCAs: make(map[string]*LocalCA),
	}

	// Collect all private CA configs: private_cas[] + private_ca (backward compat).
	allCAs := append([]PrivateCAConfig{}, cfg.PrivateCAs...)
	if cfg.PrivateCA != nil {
		allCAs = append(allCAs, *cfg.PrivateCA)
	}

	for _, caCfg := range allCAs {
		if caCfg.CertFile == "" || caCfg.KeyFile == "" {
			continue
		}
		ca, err := LoadLocalCA(caCfg)
		if err != nil {
			return nil, err
		}
		if caCfg.CAConnectorID != "" {
			w.localCAs[caCfg.CAConnectorID] = ca
			log.Printf("[connector] private CA loaded: ca_connector_id=%s cert=%s validity=%dd (governed)", caCfg.CAConnectorID, caCfg.CertFile, ca.validDays)
		} else {
			w.legacyCA = ca
			log.Printf("[connector] private CA loaded: cert=%s validity=%dd (WARNING: no ca_connector_id — signing without DTP governance; add ca_connector_id to enable governance)", caCfg.CertFile, ca.validDays)
		}
	}
	return w, nil
}

const certReportInterval = 6 * time.Hour
const inventorySyncInterval = 6 * time.Hour

// Run polls in a loop until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	log.Printf("[connector] starting %s — polling %s every %s", w.version, w.cfg.CertForgeURL, w.cfg.PollInterval)

	jobTicker := time.NewTicker(w.cfg.PollInterval)
	certTicker := time.NewTicker(certReportInterval)
	inventoryTicker := time.NewTicker(inventorySyncInterval)
	defer jobTicker.Stop()
	defer certTicker.Stop()
	defer inventoryTicker.Stop()

	// Baseline work on startup.
	w.poll(ctx)
	w.pollSignRequests()
	w.reportCurrentCerts(ctx)
	w.syncInventory(ctx)
	w.registerCapabilities()

	for {
		select {
		case <-ctx.Done():
			log.Printf("[connector] shutting down")
			return
		case <-jobTicker.C:
			w.poll(ctx)
			w.pollSignRequests()
		case <-certTicker.C:
			w.reportCurrentCerts(ctx)
		case <-inventoryTicker.C:
			w.syncInventory(ctx)
		}
	}
}

func (w *Worker) registerCapabilities() {
	if err := w.client.RegisterCapabilities(SupportedDeviceTypes(), w.cfg.ConnectorID); err != nil {
		log.Printf("[connector] register capabilities: %v", err)
	}
}

// syncInventory pushes the full cert inventory of the local CA to CertForge.
// Does nothing when ca_connector_id is not configured or no inventory source is set.
func (w *Worker) syncInventory(ctx context.Context) {
	ca := w.cfg.PrivateCA
	if ca == nil || ca.CAConnectorID == "" {
		return
	}
	if ca.IssuedCertsDir == "" && ca.VaultPKI == nil {
		return
	}

	// Fetch scope from CertForge.
	connectors, err := w.client.GetCAConnectors()
	if err != nil {
		log.Printf("[connector] inventory sync: fetch ca-connectors: %v", err)
		return
	}
	var scope ConnectorScope
	found := false
	for _, c := range connectors {
		if c.ID == ca.CAConnectorID {
			scope = c.Scope
			found = true
			break
		}
	}
	if !found {
		log.Printf("[connector] inventory sync: ca connector %s not found in CertForge", ca.CAConnectorID)
		return
	}

	var certs []InventoryCert
	if ca.VaultPKI != nil {
		certs, err = FetchVaultPKICerts(*ca.VaultPKI, scope)
		if err != nil {
			log.Printf("[connector] inventory sync: vault-pki: %v", err)
			return
		}
	} else {
		var revokedSerials map[string]bool
		if ca.CRLFile != "" {
			revokedSerials, err = ReadRevokedSerials(ca.CRLFile)
			if err != nil {
				log.Printf("[connector] inventory sync: read CRL: %v", err)
				// Non-fatal — continue without revocation filtering.
			}
		}
		certs, err = ScanIssuedCerts(ca.IssuedCertsDir, scope, revokedSerials)
		if err != nil {
			log.Printf("[connector] inventory sync: scan %s: %v", ca.IssuedCertsDir, err)
			return
		}
	}

	count, err := w.client.PushInventory(ca.CAConnectorID, certs)
	if err != nil {
		log.Printf("[connector] inventory sync: push %d certs: %v", len(certs), err)
		return
	}
	log.Printf("[connector] inventory sync: accepted %d/%d certs", count, len(certs))
}

// reportCurrentCerts reads the live TLS cert from every device in CertForge
// and reports expiry, CN, and SANs back. Falls back to the yaml device list
// if the CertForge API call fails.
func (w *Worker) reportCurrentCerts(ctx context.Context) {
	devices, err := w.client.GetDevices()
	if err != nil {
		log.Printf("[connector] fetch device list: %v — falling back to yaml", err)
		// Fall back to yaml device list.
		for _, d := range w.cfg.Devices {
			w.reportOneCert(d.ID, d.Host, d.Port, d.SkipVerify)
		}
		return
	}
	for _, d := range devices {
		w.reportOneCert(d.ID, d.Host, d.Port, d.SkipVerify)
	}
}

func (w *Worker) reportOneCert(deviceID, host string, port int, skipVerify bool) {
	if port == 0 {
		port = 443
	}
	info, err := tlsReadCert(host, port, skipVerify)
	if err != nil {
		log.Printf("[connector] cert-read %s (%s:%d): %v", deviceID, host, port, err)
		return
	}
	if err := w.client.ReportCert(deviceID, info); err != nil {
		log.Printf("[connector] cert-report %s: %v", deviceID, err)
		return
	}
	log.Printf("[connector] cert-report %s: cn=%q not_after=%s", deviceID, info.CN, info.NotAfter.Format("2006-01-02"))
}

func (w *Worker) poll(ctx context.Context) {
	jobs, err := w.client.PollJobs()
	if err != nil {
		log.Printf("[connector] poll error: %v", err)
		return
	}
	for _, j := range jobs {
		if err := w.executeJob(ctx, j); err != nil {
			log.Printf("[connector] job %s (%s): %v", j.ID, j.DeviceName, err)
		}
	}
}

func (w *Worker) executeJob(ctx context.Context, j Job) error {
	// Cert-query jobs: TLS-read the device cert and report back; no CSR/install.
	if j.Status == "pending_query" {
		log.Printf("[connector] job %s: querying cert on %s (%s:%d)", j.ID, j.DeviceName, j.Host, j.Port)
		w.reportOneCert(j.DeviceID, j.Host, j.Port, j.SkipVerify)
		if err := w.client.MarkDone(j.ID, ""); err != nil {
			log.Printf("[connector] job %s: mark done failed: %v", j.ID, err)
		}
		return nil
	}

	// All connection details and credentials come from CertForge via the job.
	// The yaml device list is an optional override — prefer job data.
	effective := DeviceConfig{
		ID:         j.DeviceID,
		Type:       j.DeviceType,
		Host:       j.Host,
		Port:       j.Port,
		TLSContext: j.TLSContext,
		SkipVerify: j.SkipVerify,
		Username:   j.Username,
		Password:   j.Password,
	}
	// If the device is also in yaml, its credentials act as a fallback.
	if devCfg := w.cfg.DeviceByID(j.DeviceID); devCfg != nil {
		if effective.Username == "" {
			effective.Username = devCfg.Username
		}
		if effective.Password == "" {
			effective.Password = devCfg.Password
		}
	}

	dev, err := effective.NewDevice()
	if err != nil {
		return fmt.Errorf("init device driver: %w", err)
	}

	log.Printf("[connector] job %s: pulling CSR from %s (%s:%d ctx %d)",
		j.ID, j.DeviceName, j.Host, j.Port, j.TLSContext)

	csrPEM, err := dev.PullCSR(ctx)
	if err != nil {
		return fmt.Errorf("pull CSR: %w", err)
	}

	usingLocalCA := len(w.localCAs) > 0 || w.legacyCA != nil
	var certPEM string

	if usingLocalCA {
		certPEM, err = w.signLocally(ctx, j.ID, csrPEM)
		if err != nil {
			return err
		}
	} else {
		log.Printf("[connector] job %s: submitting CSR to CertForge", j.ID)
		result, err := w.client.SubmitCSR(j.ID, csrPEM)
		if err != nil {
			return fmt.Errorf("submit CSR: %w", err)
		}
		if result.Certificate == "" {
			return fmt.Errorf("CertForge returned empty certificate")
		}
		certPEM = result.Certificate
	}

	log.Printf("[connector] job %s: installing cert on %s", j.ID, j.DeviceName)
	if err := dev.InstallCert(ctx, certPEM); err != nil {
		return fmt.Errorf("install cert: %w", err)
	}

	// When using a local CA, report the installed cert back to CertForge
	// so inventory and expiry tracking stay current.
	if usingLocalCA {
		if info, parseErr := parseCertPEM(certPEM); parseErr == nil {
			if repErr := w.client.ReportCert(j.DeviceID, info); repErr != nil {
				log.Printf("[connector] job %s: report cert to CertForge: %v", j.ID, repErr)
			}
		}
	}

	certForDone := ""
	if usingLocalCA {
		certForDone = certPEM
	}
	if err := w.client.MarkDone(j.ID, certForDone); err != nil {
		log.Printf("[connector] job %s: mark done failed (cert is installed): %v", j.ID, err)
	}
	log.Printf("[connector] job %s: complete — cert installed on %s", j.ID, j.DeviceName)
	return nil
}

// signLocally handles DTP-governed local signing.
// For governed CAs (ca_connector_id set): calls authorize-local-signing first (fail-closed).
// For legacy CAs (no ca_connector_id): signs directly with a warning.
func (w *Worker) signLocally(ctx context.Context, jobID, csrPEM string) (string, error) {
	// Try governed path first.
	if len(w.localCAs) > 0 {
		cn, sans, keyAlgo, keyBits := csrMeta(csrPEM)
		log.Printf("[connector] job %s: requesting DTP authorization for local signing (cn=%s)", jobID, cn)

		auth, err := w.client.AuthorizeLocalSigning(jobID, cn, sans, keyAlgo, keyBits)
		if err != nil {
			return "", fmt.Errorf("governance check failed (fail-closed — cert not signed): %w", err)
		}
		if !auth.Approved {
			return "", fmt.Errorf("local signing denied by CertForge: %s", auth.Reason)
		}

		localCA, ok := w.localCAs[auth.CAConnectorID]
		if !ok {
			return "", fmt.Errorf("CertForge authorized ca_connector_id=%s but no local CA with that ID is configured — add it to private_cas in connector.yaml", auth.CAConnectorID)
		}

		log.Printf("[connector] job %s: signing with governed local CA ca_connector_id=%s validity=%dd dtp=%s", jobID, auth.CAConnectorID, auth.ValidityDays, auth.DTPID)
		return localCA.SignCSR(csrPEM, auth.ValidityDays)
	}

	// Legacy path: no ca_connector_id — sign without governance.
	log.Printf("[connector] WARNING job %s: signing with ungoverned local CA — add ca_connector_id to private_ca to enable DTP governance", jobID)
	return w.legacyCA.SignCSR(csrPEM, 0)
}

// pollSignRequests checks each configured private CA for pending approval-flow signing
// requests (created when the CertForge server processes an approval for a private_connector CA).
// For each request, the connector signs the CSR with the appropriate local CA and posts the cert back.
func (w *Worker) pollSignRequests() {
	for connID, ca := range w.localCAs {
		reqs, err := w.client.GetSignRequests(connID)
		if err != nil {
			log.Printf("[connector] sign-requests %s: %v", connID, err)
			continue
		}
		for _, req := range reqs {
			log.Printf("[connector] sign-request %s: signing for %s", req.ID, req.Domains)
			certPEM, err := ca.SignCSR(req.CSRPEM, ca.validDays)
			if err != nil {
				log.Printf("[connector] sign-request %s: sign CSR: %v", req.ID, err)
				continue
			}
			if err := w.client.SubmitSignRequest(connID, req.ID, certPEM); err != nil {
				log.Printf("[connector] sign-request %s: submit: %v", req.ID, err)
				continue
			}
			log.Printf("[connector] sign-request %s: complete (%s)", req.ID, req.Domains)
		}
	}
}

// csrMeta extracts CN, SANs, key algorithm and key size from a CSR PEM for the
// authorize-local-signing call. Returns empty strings on parse failure (server will reject).
func csrMeta(csrPEM string) (cn string, sans []string, keyAlgo string, keyBits int) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return
	}
	cn = csr.Subject.CommonName
	sans = csr.DNSNames
	switch pub := csr.PublicKey.(type) {
	case *rsa.PublicKey:
		keyAlgo = "rsa"
		keyBits = pub.N.BitLen()
	case *ecdsa.PublicKey:
		keyAlgo = "ecdsa"
		keyBits = pub.Params().BitSize
	}
	return
}
