package connector

import (
	"context"
	"fmt"
	"log"
	"time"
)

// Worker polls CertForge for device jobs and executes them.
type Worker struct {
	cfg      *Config
	client   *Client
	localCA  *LocalCA // non-nil when private_ca is configured
}

func NewWorker(cfg *Config) (*Worker, error) {
	w := &Worker{
		cfg:    cfg,
		client: NewClient(cfg.CertForgeURL, cfg.APIKey),
	}
	if cfg.PrivateCA != nil {
		ca, err := LoadLocalCA(*cfg.PrivateCA)
		if err != nil {
			return nil, err
		}
		w.localCA = ca
		log.Printf("[connector] private CA loaded from %s (validity %d days)", cfg.PrivateCA.CertFile, ca.validDays)
	}
	return w, nil
}

const certReportInterval = 6 * time.Hour

// Run polls in a loop until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	log.Printf("[connector] starting — polling %s every %s", w.cfg.CertForgeURL, w.cfg.PollInterval)

	jobTicker := time.NewTicker(w.cfg.PollInterval)
	certTicker := time.NewTicker(certReportInterval)
	defer jobTicker.Stop()
	defer certTicker.Stop()

	// Baseline cert read on startup.
	w.poll(ctx)
	w.reportCurrentCerts(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[connector] shutting down")
			return
		case <-jobTicker.C:
			w.poll(ctx)
		case <-certTicker.C:
			w.reportCurrentCerts(ctx)
		}
	}
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

	var certPEM string
	if w.localCA != nil {
		log.Printf("[connector] job %s: signing CSR with local CA", j.ID)
		certPEM, err = w.localCA.SignCSR(csrPEM)
		if err != nil {
			return fmt.Errorf("local CA sign: %w", err)
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
	if w.localCA != nil {
		if info, parseErr := parseCertPEM(certPEM); parseErr == nil {
			if repErr := w.client.ReportCert(j.DeviceID, info); repErr != nil {
				log.Printf("[connector] job %s: report cert to CertForge: %v", j.ID, repErr)
			}
		}
	}

	// Send the locally-signed cert so CertForge can store it for inventory.
	certForDone := ""
	if w.localCA != nil {
		certForDone = certPEM
	}
	if err := w.client.MarkDone(j.ID, certForDone); err != nil {
		log.Printf("[connector] job %s: mark done failed (cert is installed): %v", j.ID, err)
	}
	log.Printf("[connector] job %s: complete — cert installed on %s", j.ID, j.DeviceName)
	return nil
}
