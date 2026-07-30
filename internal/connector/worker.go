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
// and reports its expiry to CertForge. This gives CertForge visibility into
// certs that were not issued through the connector (e.g. pre-existing certs).
func (w *Worker) reportCurrentCerts(ctx context.Context) {
	for _, d := range w.cfg.Devices {
		port := d.Port
		if port == 0 {
			port = 443
		}
		notAfter, err := tlsReadCert(d.Host, port, d.SkipVerify)
		if err != nil {
			log.Printf("[connector] cert-read %s (%s:%d): %v", d.ID, d.Host, port, err)
			continue
		}
		if err := w.client.ReportCert(d.ID, notAfter); err != nil {
			log.Printf("[connector] cert-report %s: %v", d.ID, err)
			continue
		}
		log.Printf("[connector] cert-report %s: not_after=%s", d.ID, notAfter.Format("2006-01-02"))
	}
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

	dev, err := devCfg.NewDevice()
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
