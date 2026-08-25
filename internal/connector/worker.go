package connector

import (
	"context"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/certforge/certforge-connector/internal/device"
)

// Worker polls CertForge for device jobs and executes them.
type Worker struct {
	cfg      *Config
	client   *Client
	version  string
	// localCAs maps ca_connector_id → LocalCA for governed local signing (DTP-validated).
	// Populated from private_cas[] entries (and private_ca if it has a ca_connector_id).
	localCAs map[string]*LocalCA
	// legacyCA is no longer used; kept as a nil sentinel to detect misconfigured YAML
	// entries without ca_connector_id and produce a clear startup error.
	legacyCA *LocalCA
	// disabled is true when CertForge reports this connector is disabled.
	// All polling is suppressed until registerCapabilities succeeds again.
	disabled bool
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
			// Ungoverned signing (no ca_connector_id) is no longer supported.
			// Every private CA must have a ca_connector_id so CertForge can enforce
			// Domain Trust Policy before the connector signs.
			return nil, fmt.Errorf(
				"private CA %q has no ca_connector_id — ungoverned signing is not permitted.\n"+
					"  1. Go to Settings → CA Connectors in CertForge and create a Private CA connector.\n"+
					"  2. Copy the connector ID and add ca_connector_id: <id> to this private_ca entry.\n"+
					"  3. Link the CA to a Domain Trust Policy so CertForge can authorize signing requests.",
				caCfg.CertFile,
			)
		}
	}
	return w, nil
}

const certReportInterval = 6 * time.Hour
const inventorySyncInterval = 6 * time.Hour
const capsCheckInterval = 5 * time.Minute

// Run polls in a loop until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	log.Printf("[connector] starting %s - polling %s every %s", w.version, w.cfg.CertForgeURL, w.cfg.PollInterval)

	currentPollInterval := w.cfg.PollInterval
	jobTicker := time.NewTicker(currentPollInterval)
	certTicker := time.NewTicker(certReportInterval)
	inventoryTicker := time.NewTicker(inventorySyncInterval)
	capsTicker := time.NewTicker(capsCheckInterval)
	defer jobTicker.Stop()
	defer certTicker.Stop()
	defer inventoryTicker.Stop()
	defer capsTicker.Stop()

	// Check capabilities first so disabled state is known before any polling.
	// Apply any server-delivered poll interval right away.
	if serverInterval := w.registerCapabilities(); serverInterval > 0 && serverInterval != currentPollInterval {
		log.Printf("[connector] server-delivered poll interval: %s (was %s)", serverInterval, currentPollInterval)
		currentPollInterval = serverInterval
		jobTicker.Reset(currentPollInterval)
	}
	if !w.cfg.NoDeviceJobs {
		w.poll(ctx)
		w.pollSignRequests()
		w.reportDeviceVersions(ctx)
		w.reportCurrentCerts(ctx)
	}
	w.syncInventory(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[connector] shutting down")
			return
		case <-jobTicker.C:
			if !w.cfg.NoDeviceJobs {
				w.poll(ctx)
				w.pollSignRequests()
			}
		case <-certTicker.C:
			if !w.cfg.NoDeviceJobs {
				w.reportCurrentCerts(ctx)
			}
		case <-inventoryTicker.C:
			w.syncInventory(ctx)
		case <-capsTicker.C:
			wasDisabled := w.disabled
			serverInterval := w.registerCapabilities()
			// Apply a changed server-delivered interval without restarting.
			if serverInterval > 0 && serverInterval != currentPollInterval {
				log.Printf("[connector] poll interval changed by platform: %s → %s", currentPollInterval, serverInterval)
				currentPollInterval = serverInterval
				jobTicker.Reset(currentPollInterval)
			}
			if wasDisabled && !w.disabled && !w.cfg.NoDeviceJobs {
				w.poll(ctx)
				w.pollSignRequests()
			}
		}
	}
}

// registerCapabilities registers this connector's capabilities with the platform and
// returns the server-delivered poll interval (0 if the platform has not set one).
func (w *Worker) registerCapabilities() time.Duration {
	// Collect all CA connector IDs; the server checks each and returns 403 if any are disabled.
	var ids []string
	for connID := range w.localCAs {
		ids = append(ids, connID)
	}
	if w.cfg.ConnectorID != "" {
		ids = append(ids, w.cfg.ConnectorID)
	}

	// Query CA backend versions: YAML-configured connectors first, then server-provided
	// (best-effort; failure here does not block capability registration).
	backendVersions := make(map[string]string)
	allCAs := append([]PrivateCAConfig{}, w.cfg.PrivateCAs...)
	if w.cfg.PrivateCA != nil {
		allCAs = append(allCAs, *w.cfg.PrivateCA)
	}
	for _, ca := range allCAs {
		if ca.VaultPKI != nil && ca.CAConnectorID != "" {
			if ver, err := queryVaultVersion(ca.VaultPKI.Addr); err == nil && ver != "" {
				backendVersions[ca.CAConnectorID] = "Vault " + ver
			}
		}
	}
	// Also query vault versions for server-configured connectors not covered by YAML.
	if serverConns, err := w.client.GetCAConnectors(); err == nil {
		for _, sc := range serverConns {
			if _, already := backendVersions[sc.ID]; already {
				continue
			}
			if sc.VaultPKI != nil && sc.VaultPKI.Addr != "" {
				if ver, err := queryVaultVersion(sc.VaultPKI.Addr); err == nil && ver != "" {
					backendVersions[sc.ID] = "Vault " + ver
				}
			}
		}
	}

	result, err := w.client.RegisterCapabilities(SupportedDeviceTypes(), ids, backendVersions, w.version)
	if err != nil {
		if isConnectorDisabled(err) {
			if !w.disabled {
				log.Printf("[connector] connector is disabled in CertForge - standing by until re-enabled")
				w.disabled = true
			}
			return 0
		}
		log.Printf("[connector] register capabilities: %v", err)
		return 0
	}
	if w.disabled {
		log.Printf("[connector] connector is now enabled - resuming normal operation")
		w.disabled = false
	}
	if result.PollIntervalSeconds > 0 {
		return time.Duration(result.PollIntervalSeconds) * time.Second
	}
	return 0
}

// queryVaultVersion fetches the Vault version from the unauthenticated /v1/sys/health endpoint.
func queryVaultVersion(addr string) (string, error) {
	hc := &http.Client{
		Timeout: 5 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec - version check only
		},
	}
	resp, err := hc.Get(addr + "/v1/sys/health")
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	var info struct {
		Version string `json:"version"`
	}
	b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
	if err := json.Unmarshal(b, &info); err != nil {
		return "", err
	}
	return info.Version, nil
}

// syncInventory pushes the full cert inventory for every CA connector this agent
// is responsible for. It discovers connectors from the CertForge server (which may
// include vault_pki config now stored in the CertForge UI), and falls back to
// YAML-configured private_ca/private_cas entries for any not covered by the server.
func (w *Worker) syncInventory(ctx context.Context) {
	if w.disabled {
		return
	}

	// Pull current connector list from CertForge (scope + optional server-side vault config).
	serverConns, err := w.client.GetCAConnectors()
	if err != nil {
		log.Printf("[connector] inventory sync: fetch ca-connectors: %v", err)
		return
	}
	if len(serverConns) == 0 {
		return
	}

	// Build a lookup of YAML-configured private CAs by ca_connector_id.
	yamlCAByID := make(map[string]*PrivateCAConfig)
	allYAMLCAs := append([]PrivateCAConfig{}, w.cfg.PrivateCAs...)
	if w.cfg.PrivateCA != nil {
		allYAMLCAs = append(allYAMLCAs, *w.cfg.PrivateCA)
	}
	for i := range allYAMLCAs {
		if id := allYAMLCAs[i].CAConnectorID; id != "" {
			yamlCAByID[id] = &allYAMLCAs[i]
		}
	}

	for _, sc := range serverConns {
		w.syncOneConnector(ctx, sc, yamlCAByID[sc.ID])
	}
}

// syncOneConnector syncs inventory for a single CA connector.
// vaultCfg precedence: server-provided (sc.VaultPKI) > YAML override (yamlCA.VaultPKI).
// issued_certs_dir and crl_file always come from YAML (filesystem paths can't live in DB).
func (w *Worker) syncOneConnector(ctx context.Context, sc CAConnectorInfo, yamlCA *PrivateCAConfig) {
	// Resolve effective vault config: server first, YAML fallback.
	var vaultCfg *VaultPKIConfig
	if sc.VaultPKI != nil && sc.VaultPKI.Addr != "" {
		vaultCfg = sc.VaultPKI
	} else if yamlCA != nil && yamlCA.VaultPKI != nil {
		vaultCfg = yamlCA.VaultPKI
	}

	issuedDir := ""
	crlFile := ""
	if yamlCA != nil {
		issuedDir = yamlCA.IssuedCertsDir
		crlFile = yamlCA.CRLFile
	}

	if vaultCfg == nil && issuedDir == "" {
		return // no inventory source for this connector
	}

	var certs []InventoryCert
	if vaultCfg != nil {
		certs, err := FetchVaultPKICerts(*vaultCfg, sc.Scope)
		if err != nil {
			log.Printf("[connector] inventory sync %s (%s): vault-pki: %v", sc.ID, sc.Name, err)
			_ = w.client.ReportSyncError(sc.ID, "vault-pki: "+err.Error())
			return
		}
		count, err := w.client.PushInventory(sc.ID, certs)
		if err != nil {
			log.Printf("[connector] inventory sync %s (%s): push %d certs: %v", sc.ID, sc.Name, len(certs), err)
			return
		}
		log.Printf("[connector] inventory sync %s (%s): accepted %d/%d certs (vault)", sc.ID, sc.Name, count, len(certs))
		return
	}

	// File-system scan path.
	var revokedSerials map[string]bool
	if crlFile != "" {
		if rs, err := ReadRevokedSerials(crlFile); err != nil {
			log.Printf("[connector] inventory sync %s (%s): read CRL: %v", sc.ID, sc.Name, err)
		} else {
			revokedSerials = rs
		}
	}
	var err error
	certs, err = ScanIssuedCerts(issuedDir, sc.Scope, revokedSerials)
	if err != nil {
		log.Printf("[connector] inventory sync %s (%s): scan %s: %v", sc.ID, sc.Name, issuedDir, err)
		_ = w.client.ReportSyncError(sc.ID, "scan: "+err.Error())
		return
	}
	count, err := w.client.PushInventory(sc.ID, certs)
	if err != nil {
		log.Printf("[connector] inventory sync %s (%s): push %d certs: %v", sc.ID, sc.Name, len(certs), err)
		return
	}
	log.Printf("[connector] inventory sync %s (%s): accepted %d/%d certs (dir)", sc.ID, sc.Name, count, len(certs))
}

// reportDeviceVersions queries the firmware/software version from every device
// that supports it (device.Versioned). Called at startup as a quick connectivity
// heartbeat — surfaces version info and catches misconfigured device credentials early.
func (w *Worker) reportDeviceVersions(ctx context.Context) {
	if w.disabled {
		return
	}
	devices, err := w.client.GetDevices()
	if err != nil {
		log.Printf("[connector] device version check: fetch devices: %v", err)
		return
	}
	for _, d := range devices {
		if d.Status == "inactive" {
			continue
		}
		cfg := DeviceConfig{
			ID:         d.ID,
			Type:       d.Type,
			Host:       d.Host,
			MgmtHost:   d.MgmtHost,
			Port:       d.Port,
			TLSContext: d.TLSContext,
			SkipVerify: d.SkipVerify,
			Username:   d.Username,
			Password:   d.Password,
		}
		// YAML can supplement server-delivered config: credentials as fallback,
		// and skip_verify as an OR (local admin can grant it even if server says false).
		if yamlDev := w.cfg.DeviceByID(d.ID); yamlDev != nil {
			if cfg.Username == "" {
				cfg.Username = yamlDev.Username
			}
			if cfg.Password == "" {
				cfg.Password = yamlDev.Password
			}
			if yamlDev.SkipVerify {
				cfg.SkipVerify = true
			}
		}
		if cfg.Username == "" || cfg.Password == "" {
			log.Printf("[connector] device %s (%s): version check skipped: missing credentials", d.ID, d.Host)
			continue
		}
		log.Printf("[connector] device %s (%s): version check: skip_verify=%v", d.ID, d.Host, cfg.SkipVerify)
		drv, err := cfg.NewDevice()
		if err != nil {
			log.Printf("[connector] device %s (%s): init driver: %v", d.ID, d.Host, err)
			continue
		}
		v, ok := drv.(device.Versioned)
		if !ok {
			continue // driver doesn't expose firmware version
		}
		ver, err := v.SoftwareVersion(ctx)
		if err != nil {
			log.Printf("[connector] device %s (%s): version check failed: %v", d.ID, d.Host, err)
			continue
		}
		log.Printf("[connector] device %s (%s): software version %s", d.ID, d.Host, ver)
		if repErr := w.client.ReportDeviceInfo(d.ID, ver); repErr != nil {
			log.Printf("[connector] device %s: report version: %v", d.ID, repErr)
		}
	}
}

// reportCurrentCerts reads the live TLS cert from every device in CertForge
// and reports expiry, CN, and SANs back. Falls back to the yaml device list
// if the CertForge API call fails.
func (w *Worker) reportCurrentCerts(ctx context.Context) {
	if w.disabled {
		return
	}
	devices, err := w.client.GetDevices()
	if err != nil {
		log.Printf("[connector] fetch device list: %v - falling back to yaml", err)
		// Fall back to yaml device list.
		for _, d := range w.cfg.Devices {
			w.reportOneCert(d.ID, d.Host, d.Port, d.SkipVerify)
		}
		return
	}
	for _, d := range devices {
		if d.Status == "inactive" {
			log.Printf("[connector] device %s (%s): disabled in CertForge - skipping", d.ID, d.Host)
			continue
		}
		// Try to instantiate the driver so devices that implement CertReader can
		// report the cert from their managed profile via API rather than TLS-dialing
		// the management port (which may present a different cert).
		cfg := DeviceConfig{
			ID:         d.ID,
			Type:       d.Type,
			Host:       d.Host,
			MgmtHost:   d.MgmtHost,
			Port:       d.Port,
			TLSContext: d.TLSContext,
			SkipVerify: d.SkipVerify,
			Username:   d.Username,
			Password:   d.Password,
		}
		if yamlDev := w.cfg.DeviceByID(d.ID); yamlDev != nil {
			if cfg.Username == "" {
				cfg.Username = yamlDev.Username
			}
			if cfg.Password == "" {
				cfg.Password = yamlDev.Password
			}
			if yamlDev.SkipVerify {
				cfg.SkipVerify = true
			}
		}
		if cfg.Username != "" && cfg.Password != "" {
			if drv, err := cfg.NewDevice(); err == nil {
				w.reportOneCertViaDevice(ctx, d.ID, d.Host, d.Port, d.SkipVerify, drv)
				continue
			}
		}
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

// reportOneCertViaDevice uses the device's CertReader interface (if implemented)
// to read the managed cert via API rather than TLS-dialing the management port.
// Falls back to reportOneCert if the device doesn't implement CertReader or the
// API call fails.
func (w *Worker) reportOneCertViaDevice(ctx context.Context, deviceID, host string, port int, skipVerify bool, dev device.Device) {
	cr, ok := dev.(device.CertReader)
	if !ok {
		w.reportOneCert(deviceID, host, port, skipVerify)
		return
	}
	di, err := cr.ReadCert(ctx)
	if err != nil {
		log.Printf("[connector] cert-read %s: api read failed (%v), falling back to TLS dial", deviceID, err)
		w.reportOneCert(deviceID, host, port, skipVerify)
		return
	}
	notAfter, _ := time.Parse(time.RFC3339, di.NotAfter)
	info := CertInfo{
		CN:       di.CN,
		SANs:     di.SANs,
		NotAfter: notAfter,
	}
	if err := w.client.ReportCert(deviceID, info); err != nil {
		log.Printf("[connector] cert-report %s: %v", deviceID, err)
		return
	}
	log.Printf("[connector] cert-report %s: cn=%q not_after=%s (via api)", deviceID, di.CN, notAfter.Format("2006-01-02"))
}

func (w *Worker) poll(ctx context.Context) {
	if w.disabled {
		return
	}
	jobs, err := w.client.PollJobs()
	if err != nil {
		log.Printf("[connector] poll error: %v", err)
		return
	}
	if len(jobs) == 0 {
		log.Printf("[connector] poll: ok, no pending jobs")
		return
	}
	log.Printf("[connector] poll: %d job(s) to process", len(jobs))
	for _, j := range jobs {
		if err := w.executeJob(ctx, j); err != nil {
			log.Printf("[connector] job %s (%s): %v", j.ID, j.DeviceName, err)
		}
	}
}

func (w *Worker) executeJob(ctx context.Context, j Job) error {
	// pending_approval: waiting for a human to approve the request in CertForge.
	if j.Status == "pending_approval" {
		log.Printf("[connector] job %s: awaiting approval in CertForge — waiting", j.ID)
		return nil
	}
	// pending_acme: server is running ACME in the background; wait for cert_ready.
	if j.Status == "pending_acme" {
		log.Printf("[connector] job %s: ACME issuance in progress on server — waiting", j.ID)
		return nil
	}

	// cert_ready: server issued the cert via ACME after the connector's submitCSR returned.
	// Install the private key (if the server generated it externally) then the cert.
	if j.Status == "cert_ready" && j.Certificate != "" {
		log.Printf("[connector] job %s: cert_ready — installing on %s", j.ID, j.DeviceName)
		effective := DeviceConfig{
			ID:         j.DeviceID,
			Type:       j.DeviceType,
			Host:       j.Host,
			MgmtHost:   j.MgmtHost,
			Port:       j.Port,
			TLSContext: j.TLSContext,
			SkipVerify: j.SkipVerify,
			Username:   j.Username,
			Password:   j.Password,
		}
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
		// When the connector generated the key externally (ACME SAN flow — device CSR
		// API can't include SANs), the server holds the key and returns it here.
		// Install the key first so the device has it before the cert arrives.
		if j.ExternalKeyPEM != "" {
			if ki, ok := dev.(device.PrivateKeyInstaller); ok {
				log.Printf("[connector] job %s: installing external private key on %s", j.ID, j.DeviceName)
				if err := ki.InstallPrivateKey(ctx, j.ExternalKeyPEM); err != nil {
					return fmt.Errorf("install private key: %w", err)
				}
			}
		}
		if err := dev.InstallCert(ctx, j.Certificate); err != nil {
			return fmt.Errorf("install cert: %w", err)
		}
		// Push the signing chain (intermediate + root) into the device's trusted root
		// store so it can serve the full chain during TLS handshakes.
		// InstallTrustedRoot also flushes the cached server cert (slot 1) after
		// installing the CA chain (slots 2+), so its error covers both operations.
		if installer, ok := dev.(device.TrustedRootInstaller); ok {
			if chain := pemChain(j.Certificate); chain != "" {
				log.Printf("[connector] job %s: installing trusted root chain on %s", j.ID, j.DeviceName)
				if err := installer.InstallTrustedRoot(ctx, chain); err != nil {
					// CA chain or server cert install failed — do not mark done.
					// The job stays cert_ready on the server so the next poll retries.
					log.Printf("[connector] job %s: CA chain / cert install failed: %v", j.ID, err)
					return err
				}
			}
		}
		// Persist the changes — some devices (e.g. AudioCodes) stage cert uploads in
		// RAM and revert on restart until an explicit save is issued.
		if saver, ok := dev.(device.ConfigSaver); ok {
			log.Printf("[connector] job %s: saving configuration on %s", j.ID, j.DeviceName)
			if err := saver.SaveConfiguration(ctx); err != nil {
				log.Printf("[connector] job %s: save configuration: %v (cert uploaded, marking done anyway)", j.ID, err)
			}
		}
		if err := w.client.MarkDone(j.ID, ""); err != nil {
			log.Printf("[connector] job %s: mark done failed: %v", j.ID, err)
		}
		log.Printf("[connector] job %s: complete - cert installed on %s", j.ID, j.DeviceName)
		return nil
	}

	// Cert-query jobs: read the device cert and report back; no CSR/install.
	// Prefer the device driver's CertReader (e.g. F5 REST API reads the managed
	// profile cert, not the management-port self-signed cert). Fall back to a raw
	// TLS dial if no credentials are available or the driver doesn't implement ReadCert.
	if j.Status == "pending_query" {
		log.Printf("[connector] job %s: querying cert on %s (%s:%d)", j.ID, j.DeviceName, j.Host, j.Port)
		queryCfg := DeviceConfig{
			ID:         j.DeviceID,
			Type:       j.DeviceType,
			Host:       j.Host,
			MgmtHost:   j.MgmtHost,
			Port:       j.Port,
			TLSContext: j.TLSContext,
			SkipVerify: j.SkipVerify,
			Username:   j.Username,
			Password:   j.Password,
		}
		if yd := w.cfg.DeviceByID(j.DeviceID); yd != nil {
			if queryCfg.Username == "" {
				queryCfg.Username = yd.Username
			}
			if queryCfg.Password == "" {
				queryCfg.Password = yd.Password
			}
		}
		if queryCfg.Username != "" && queryCfg.Password != "" {
			if drv, drvErr := queryCfg.NewDevice(); drvErr == nil {
				w.reportOneCertViaDevice(ctx, j.DeviceID, j.Host, j.Port, j.SkipVerify, drv)
			} else {
				w.reportOneCert(j.DeviceID, j.Host, j.Port, j.SkipVerify)
			}
		} else {
			w.reportOneCert(j.DeviceID, j.Host, j.Port, j.SkipVerify)
		}
		if err := w.client.MarkDone(j.ID, ""); err != nil {
			log.Printf("[connector] job %s: mark done failed: %v", j.ID, err)
		}
		return nil
	}

	// All connection details and credentials come from CertForge via the job.
	// The yaml device list is an optional override - prefer job data.
	effective := DeviceConfig{
		ID:         j.DeviceID,
		Type:       j.DeviceType,
		Host:       j.Host,
		MgmtHost:   j.MgmtHost,
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

	// Report firmware version if the driver supports it (non-fatal).
	if v, ok := dev.(device.Versioned); ok {
		if ver, verErr := v.SoftwareVersion(ctx); verErr == nil && ver != "" {
			log.Printf("[connector] job %s: device software version: %s", j.ID, ver)
			if repErr := w.client.ReportDeviceInfo(j.DeviceID, ver); repErr != nil {
				log.Printf("[connector] job %s: report device info: %v", j.ID, repErr)
			}
		}
	}

	// CSRGenerator devices generate a fresh key pair and return the CSR in one
	// call — no pre-existing key or manual setup required on the device.
	// Fallback to PullCSR for drivers that don't implement CSRGenerator.
	// PrivateKeyInstaller devices (AudioCodes) accept an externally-generated key+CSR,
	// so SANs can be added there even though the firmware's own CSR generation API
	// doesn't support subjectAltName. generateExternalCSR (below) always includes the
	// CN as a DNS SAN, so we must NOT add SANs to the device-side CSR subject — doing
	// so would trigger a 400 "JSON form syntax error" from the firmware.
	_, isKeyInstaller := dev.(device.PrivateKeyInstaller)

	var csrPEM string
	if gen, ok := dev.(device.CSRGenerator); ok {
		log.Printf("[connector] job %s: generating new key+CSR on %s", j.ID, j.DeviceName)
		subject := device.CertSubject{
			CN: j.SubjectCN,
			O:  j.SubjectO,
			OU: j.SubjectOU,
			L:  j.SubjectL,
			ST: j.SubjectST,
			C:  j.SubjectC,
		}
		if subject.CN == "" {
			subject.CN = j.Host
		}
		// Only include the CN as a DNS SAN in the device-side CSR when the device can
		// handle it and isn't a PrivateKeyInstaller. For PrivateKeyInstaller devices
		// (AudioCodes 7.40A), the firmware rejects subjectAltName with HTTP 400 —
		// the SAN is instead added by generateExternalCSR in the ACME path below.
		if j.IncludeHostAsSAN && !isKeyInstaller && net.ParseIP(subject.CN) == nil && subject.CN != "" {
			subject.SANs = []string{subject.CN}
		}
		csrPEM, err = gen.GenerateCSR(ctx, subject)
		if err != nil {
			return fmt.Errorf("generate CSR: %w", err)
		}
	} else {
		log.Printf("[connector] job %s: pulling CSR from %s (%s:%d ctx %d)",
			j.ID, j.DeviceName, j.Host, j.Port, j.TLSContext)
		csrPEM, err = dev.PullCSR(ctx)
		if err != nil {
			return fmt.Errorf("pull CSR: %w", err)
		}
	}

	var certPEM string
	signedLocally := false

	if len(w.localCAs) > 0 || w.legacyCA != nil {
		certPEM, err = w.signLocally(ctx, j.ID, csrPEM)
		if err != nil && err != errUseSubmitCSR {
			// Permanent denial (no CA configured, DTP not found, governance check failed):
			// tell the server to mark this job failed so PollJobs stops returning it and
			// the connector stops regenerating a new device key on every poll cycle.
			if mfErr := w.client.MarkJobFailed(j.ID, err.Error()); mfErr != nil {
				log.Printf("[connector] job %s: mark-failed: %v", j.ID, mfErr)
			}
			return err
		}
		if err == nil {
			signedLocally = true
		}
	}

	if certPEM == "" {
		// If the device can accept an externally-generated private key and the CN is a
		// hostname, generate a connector-side key+CSR with DNS SANs so ACME CAs work
		// even when the device's own CSR generation API can't include SANs.
		// The key is sent to the server along with the CSR so it survives across process
		// restarts and the DTP approval wait; the server returns it with the cert_ready job.
		var externalKeyPEM string
		if _, ok := dev.(device.PrivateKeyInstaller); ok {
			cn := j.SubjectCN
			if cn == "" {
				cn = j.Host
			}
			if net.ParseIP(cn) == nil && cn != "" {
				extKey, extCSR, genErr := generateExternalCSR(cn, j.SubjectO, j.SubjectOU, j.SubjectL, j.SubjectST, j.SubjectC)
				if genErr != nil {
					log.Printf("[connector] job %s: external CSR generation failed: %v", j.ID, genErr)
				} else {
					log.Printf("[connector] job %s: generated external key+CSR for %s (ACME SAN flow)", j.ID, cn)
					csrPEM = extCSR
					externalKeyPEM = extKey
				}
			}
		}

		log.Printf("[connector] job %s: submitting CSR to CertForge", j.ID)
		result, err := w.client.SubmitCSR(j.ID, csrPEM, externalKeyPEM)
		if err != nil {
			return fmt.Errorf("submit CSR: %w", err)
		}
		// 202 cases: server queued for approval or ACME is running — nothing to do this cycle.
		if result.Status == "pending_approval" || result.Status == "pending_acme" {
			log.Printf("[connector] job %s: CSR submitted — awaiting %s on server", j.ID, result.Status)
			return nil
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

	// Push the signing chain into the device's trusted root store if supported.
	if installer, ok := dev.(device.TrustedRootInstaller); ok {
		if chain := pemChain(certPEM); chain != "" {
			log.Printf("[connector] job %s: installing trusted root chain on %s", j.ID, j.DeviceName)
			if err := installer.InstallTrustedRoot(ctx, chain); err != nil {
				log.Printf("[connector] job %s: install trusted root: %v (cert is installed, continuing)", j.ID, err)
			}
		}
	}

	// Persist the changes — some devices (e.g. AudioCodes) stage cert uploads in
	// RAM and revert on restart until an explicit save is issued.
	if saver, ok := dev.(device.ConfigSaver); ok {
		log.Printf("[connector] job %s: saving configuration on %s", j.ID, j.DeviceName)
		if err := saver.SaveConfiguration(ctx); err != nil {
			log.Printf("[connector] job %s: save configuration: %v (cert uploaded, marking done anyway)", j.ID, err)
		}
	}

	// When using a local CA, report the installed cert back to CertForge
	// so inventory and expiry tracking stay current.
	if signedLocally {
		if info, parseErr := parseCertPEM(certPEM); parseErr == nil {
			if repErr := w.client.ReportCert(j.DeviceID, info); repErr != nil {
				log.Printf("[connector] job %s: report cert to CertForge: %v", j.ID, repErr)
			}
		}
	}

	certForDone := ""
	if signedLocally {
		certForDone = certPEM
	}
	if err := w.client.MarkDone(j.ID, certForDone); err != nil {
		log.Printf("[connector] job %s: mark done failed (cert is installed): %v", j.ID, err)
	}
	log.Printf("[connector] job %s: complete - cert installed on %s", j.ID, j.DeviceName)
	return nil
}

// errUseSubmitCSR is returned by signLocally when the server indicates the device's CA
// is not a private_connector type and the connector should fall back to submitCSR.
var errUseSubmitCSR = fmt.Errorf("connector: device CA requires submitCSR path")

// signLocally handles DTP-governed local signing.
// For governed CAs (ca_connector_id set): calls authorize-local-signing first (fail-closed).
// For legacy CAs (no ca_connector_id): signs directly with a warning.
// Returns errUseSubmitCSR when the server indicates the device's CA should use submitCSR instead.
func (w *Worker) signLocally(ctx context.Context, jobID, csrPEM string) (string, error) {
	// Try governed path first.
	if len(w.localCAs) > 0 {
		cn, sans, keyAlgo, keyBits := csrMeta(csrPEM)
		log.Printf("[connector] job %s: requesting DTP authorization for local signing (cn=%s)", jobID, cn)

		auth, err := w.client.AuthorizeLocalSigning(jobID, cn, sans, keyAlgo, keyBits)
		if err != nil {
			return "", fmt.Errorf("governance check failed (fail-closed - cert not signed): %w", err)
		}
		if !auth.Approved {
			if auth.UseSubmitCSR {
				log.Printf("[connector] job %s: device CA is not private_connector type — falling back to submitCSR", jobID)
				return "", errUseSubmitCSR
			}
			return "", fmt.Errorf("local signing denied by CertForge: %s", auth.Reason)
		}

		localCA, ok := w.localCAs[auth.CAConnectorID]
		if !ok {
			// This connector doesn't hold the key for the approved CA connector.
			// Delegate to the server-mediated sign-request path: submit the CSR to
			// CertForge and let the CA connector that does hold the key pick it up.
			log.Printf("[connector] job %s: server approved ca_connector_id=%s — key not held locally, delegating to server sign-request path", jobID, auth.CAConnectorID)
			return "", errUseSubmitCSR
		}

		log.Printf("[connector] job %s: signing with governed local CA ca_connector_id=%s validity=%dd dtp=%s", jobID, auth.CAConnectorID, auth.ValidityDays, auth.DTPID)
		var subj *SubjectTemplate
		if auth.SubjectO != "" || auth.SubjectOU != "" || auth.SubjectC != "" || auth.SubjectST != "" || auth.SubjectL != "" {
			subj = &SubjectTemplate{
				O: auth.SubjectO, OU: auth.SubjectOU,
				L: auth.SubjectL, ST: auth.SubjectST, C: auth.SubjectC,
			}
		}
		return localCA.SignCSR(csrPEM, auth.ValidityDays, subj)
	}

	// No governed CAs configured and no legacy CA — nothing can sign locally.
	// This path is reached only if localCAs is empty, which NewWorker now prevents
	// when any private_ca is present (a ca_connector_id is required).
	return "", fmt.Errorf("no local CA configured for signing; add ca_connector_id to private_ca in connector.yaml")
}

// pollSignRequests checks each configured private CA for pending approval-flow signing
// requests (created when the CertForge server processes an approval for a private_connector CA).
// For each request, the connector signs the CSR with the appropriate local CA and posts the cert back.
func (w *Worker) pollSignRequests() {
	if w.disabled {
		return
	}
	for connID, ca := range w.localCAs {
		reqs, err := w.client.GetSignRequests(connID)
		if err != nil {
			log.Printf("[connector] sign-requests %s: %v", connID, err)
			continue
		}
		for _, req := range reqs {
			validity := ca.validDays
			if req.ValidityDays > 0 {
				validity = req.ValidityDays // honour the issuance profile validity from the DTP
			}
			log.Printf("[connector] sign-request %s: signing for %s (validity=%dd)", req.ID, req.Domains, validity)
			certPEM, err := ca.SignCSR(req.CSRPEM, validity, nil) // no subject template for approval-flow requests
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
// pemChain returns everything after the first PEM block — the intermediate and
// root CA certs bundled by CertForge after the leaf certificate.
func pemChain(fullPEM string) string {
	_, rest := pem.Decode([]byte(fullPEM))
	return strings.TrimSpace(string(rest))
}

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

// generateExternalCSR creates a 2048-bit RSA key pair and a CSR with the given CN
// as both the Subject CN and a DNS SAN. Used when the device's CSR generation API
// can't include SANs (e.g. AudioCodes firmware 7.40) but the device can accept an
// externally-installed private key.
func generateExternalCSR(cn, o, ou, l, st, c string) (keyPEM, csrPEM string, err error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return "", "", fmt.Errorf("generate RSA key: %w", err)
	}
	subj := pkix.Name{CommonName: cn}
	if o != "" {
		subj.Organization = []string{o}
	}
	if ou != "" {
		subj.OrganizationalUnit = []string{ou}
	}
	if l != "" {
		subj.Locality = []string{l}
	}
	if st != "" {
		subj.Province = []string{st}
	}
	if c != "" {
		subj.Country = []string{c}
	}
	tmpl := &x509.CertificateRequest{
		Subject:  subj,
		DNSNames: []string{cn},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, tmpl, key)
	if err != nil {
		return "", "", fmt.Errorf("create CSR: %w", err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return "", "", fmt.Errorf("marshal key: %w", err)
	}
	keyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	csrPEM = string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))
	return keyPEM, csrPEM, nil
}
