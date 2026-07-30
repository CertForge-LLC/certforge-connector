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

// Run polls in a loop until ctx is cancelled.
func (w *Worker) Run(ctx context.Context) {
	log.Printf("[connector] starting — polling %s every %s", w.cfg.CertForgeURL, w.cfg.PollInterval)
	log.Printf("[connector] %d device(s) configured", len(w.cfg.Devices))

	ticker := time.NewTicker(w.cfg.PollInterval)
	defer ticker.Stop()

	w.poll(ctx)

	for {
		select {
		case <-ctx.Done():
			log.Printf("[connector] shutting down")
			return
		case <-ticker.C:
			w.poll(ctx)
		}
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
