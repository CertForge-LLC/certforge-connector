package connector

import (
	"context"
	"fmt"
	"log"
	"time"
)

// Worker polls CertForge for device jobs and executes them.
type Worker struct {
	cfg    *Config
	client *Client
}

func NewWorker(cfg *Config) *Worker {
	return &Worker{
		cfg:    cfg,
		client: NewClient(cfg.CertForgeURL, cfg.APIKey),
	}
}

// certReportInterval controls how often the connector reads current certs from
// devices and reports them to CertForge (independent of the renewal job poll).
const certReportInterval = 6 * time.Hour

// Run polls in a loop until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	log.Printf("[connector] starting — polling %s every %s", w.cfg.CertForgeURL, w.cfg.PollInterval)
	log.Printf("[connector] %d device(s) configured", len(w.cfg.Devices))

	jobTicker := time.NewTicker(w.cfg.PollInterval)
	certTicker := time.NewTicker(certReportInterval)
	defer jobTicker.Stop()
	defer certTicker.Stop()

	// Report current cert state immediately on startup so CertForge has baseline
	// visibility before any renewal jobs have run.
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

// reportCurrentCerts reads the live TLS certificate from each configured device
// and reports its expiry, CN, and SANs to CertForge for baseline visibility and DTP matching.
func (w *Worker) reportCurrentCerts(ctx context.Context) {
	for _, d := range w.cfg.Devices {
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
	devCfg := w.cfg.DeviceByID(j.DeviceID)
	if devCfg == nil {
		return fmt.Errorf("device %s not in connector.yaml — add it under devices:", j.DeviceID)
	}

	// Cert-query jobs: read the live cert and report it back; no CSR/install needed.
	if j.Status == "pending_query" {
		log.Printf("[connector] job %s: querying cert on %s (%s:%d)", j.ID, j.DeviceName, devCfg.Host, devCfg.Port)
		w.reportOneCert(j.DeviceID, devCfg.Host, devCfg.Port, devCfg.SkipVerify)
		if err := w.client.MarkDone(j.ID); err != nil {
			log.Printf("[connector] job %s: mark done failed: %v", j.ID, err)
		}
		return nil
	}

	// Job credentials from CertForge take precedence; yaml credentials are the fallback.
	effective := *devCfg
	if j.Username != "" {
		effective.Username = j.Username
	}
	if j.Password != "" {
		effective.Password = j.Password
	}

	dev, err := effective.NewDevice()
	if err != nil {
		return fmt.Errorf("init device driver: %w", err)
	}

	log.Printf("[connector] job %s: pulling CSR from %s (%s:%d ctx %d)",
		j.ID, j.DeviceName, devCfg.Host, devCfg.Port, devCfg.TLSContext)

	csrPEM, err := dev.PullCSR(ctx)
	if err != nil {
		return fmt.Errorf("pull CSR: %w", err)
	}

	log.Printf("[connector] job %s: submitting CSR to CertForge", j.ID)
	result, err := w.client.SubmitCSR(j.ID, csrPEM)
	if err != nil {
		return fmt.Errorf("submit CSR: %w", err)
	}
	if result.Certificate == "" {
		return fmt.Errorf("CertForge returned empty certificate")
	}

	log.Printf("[connector] job %s: installing cert on %s", j.ID, j.DeviceName)
	if err := dev.InstallCert(ctx, result.Certificate); err != nil {
		return fmt.Errorf("install cert: %w", err)
	}

	if err := w.client.MarkDone(j.ID); err != nil {
		// Cert IS installed — log and continue rather than treating as failure.
		log.Printf("[connector] job %s: mark done failed (cert is installed): %v", j.ID, err)
	}
	log.Printf("[connector] job %s: complete — cert installed on %s", j.ID, j.DeviceName)
	return nil
}
