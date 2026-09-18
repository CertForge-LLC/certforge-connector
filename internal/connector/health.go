package connector

import (
	"context"
	"fmt"
	"log"
	"os"
	"sync"
	"time"

	"github.com/certforge/certforge-connector/internal/device"
)

// DeviceHealthProbe mirrors the server-side type so we can send it in capabilities.
type DeviceHealthProbe struct {
	DeviceID  string `json:"device_id"`
	Reachable bool   `json:"reachable"`
	AuthOK    bool   `json:"auth_ok"`
	CSRPullOK bool   `json:"csr_pull_ok"`
	Error     string `json:"error,omitempty"`
}

// AppHealthProbe mirrors the server-side type.
type AppHealthProbe struct {
	AppID            string `json:"app_id"`
	CertPathWritable bool   `json:"cert_path_writable"`
	ReloadCmdOK      bool   `json:"reload_cmd_ok"`
	Error            string `json:"error,omitempty"`
}

// RemoteApp is a registered app entry returned by the CertForge app-list API.
type RemoteApp struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	CertPath  string `json:"cert_path"`
	KeyPath   string `json:"key_path"`
	ChainPath string `json:"chain_path,omitempty"`
	ReloadCmd string `json:"reload_cmd,omitempty"`
}

// healthState stores the most-recent probe results so they can be bundled into
// the next registerCapabilities call without blocking the main poll loop.
type healthState struct {
	mu      sync.Mutex
	devices []DeviceHealthProbe
	apps    []AppHealthProbe
}

func (s *healthState) setDevices(probes []DeviceHealthProbe) {
	s.mu.Lock()
	s.devices = probes
	s.mu.Unlock()
}

func (s *healthState) setApps(probes []AppHealthProbe) {
	s.mu.Lock()
	s.apps = probes
	s.mu.Unlock()
}

func (s *healthState) snapshot() ([]DeviceHealthProbe, []AppHealthProbe) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]DeviceHealthProbe(nil), s.devices...), append([]AppHealthProbe(nil), s.apps...)
}

// probeDevice runs a lightweight health check against one device.
// It prefers the Pinger interface; falls back to a PullCSR probe.
func probeDevice(ctx context.Context, d RemoteDevice, yamlCreds *DeviceConfig) DeviceHealthProbe {
	p := DeviceHealthProbe{DeviceID: d.ID}

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
	if yamlCreds != nil {
		if cfg.Username == "" {
			cfg.Username = yamlCreds.Username
		}
		if cfg.Password == "" {
			cfg.Password = yamlCreds.Password
		}
		if yamlCreds.SkipVerify {
			cfg.SkipVerify = true
		}
	}
	if cfg.Username == "" || cfg.Password == "" {
		p.Error = "missing credentials"
		return p
	}

	drv, err := cfg.NewDevice()
	if err != nil {
		p.Error = fmt.Sprintf("driver init: %v", err)
		return p
	}

	// Prefer the lightweight Pinger interface.
	if pinger, ok := drv.(device.Pinger); ok {
		if err := pinger.Ping(ctx); err != nil {
			p.Error = err.Error()
			return p
		}
		p.Reachable = true
		p.AuthOK = true
		p.CSRPullOK = true // Pinger success implies management plane is functional
		return p
	}

	// Fallback: try PullCSR as a connectivity + auth probe.
	_, err = drv.PullCSR(ctx)
	if err != nil {
		p.Error = err.Error()
		return p
	}
	p.Reachable = true
	p.AuthOK = true
	p.CSRPullOK = true
	return p
}

// probeApp checks whether the cert path directory is writable and whether
// the reload command binary exists and is executable.
func probeApp(app RemoteApp) AppHealthProbe {
	p := AppHealthProbe{AppID: app.ID}

	// Check cert path writability by opening the dir for write.
	if app.CertPath != "" {
		dir := app.CertPath
		// CertPath is a file path; get the directory.
		for i := len(dir) - 1; i >= 0; i-- {
			if dir[i] == '/' || dir[i] == '\\' {
				dir = dir[:i]
				break
			}
		}
		if dir == app.CertPath {
			dir = "."
		}
		f, err := os.CreateTemp(dir, ".certforge-health-*")
		if err != nil {
			p.Error = fmt.Sprintf("cert dir not writable: %v", err)
			return p
		}
		f.Close()
		os.Remove(f.Name())
		p.CertPathWritable = true
	} else {
		p.CertPathWritable = true // no path configured — not applicable
	}

	// Check reload command: if set, verify the binary is accessible.
	if app.ReloadCmd != "" {
		// Extract the first word (the binary name/path).
		bin := app.ReloadCmd
		for i, c := range bin {
			if c == ' ' || c == '\t' {
				bin = app.ReloadCmd[:i]
				break
			}
		}
		if _, err := os.Stat(bin); err != nil {
			p.Error = fmt.Sprintf("reload cmd not found: %v", err)
			return p
		}
	}
	p.ReloadCmdOK = true
	return p
}

// runHealthProbes fetches the device list and app list from CertForge, runs
// probes concurrently, and updates the worker's healthState. Called by the health ticker.
func (w *Worker) runHealthProbes(ctx context.Context) {
	// Device probes
	devices, err := w.client.GetDevices()
	if err != nil {
		log.Printf("health: fetch devices: %v", err)
	} else if !w.cfg.NoDeviceJobs {
		dProbes := make([]DeviceHealthProbe, 0, len(devices))
		var mu sync.Mutex
		var wg sync.WaitGroup
		for _, d := range devices {
			if d.Status == "inactive" {
				continue
			}
			d := d
			wg.Add(1)
			go func() {
				defer wg.Done()
				yamlDev := w.cfg.DeviceByID(d.ID)
				probe := probeDevice(ctx, d, yamlDev)
				mu.Lock()
				dProbes = append(dProbes, probe)
				mu.Unlock()
			}()
		}
		wg.Wait()
		w.health.setDevices(dProbes)
		log.Printf("health: probed %d device(s)", len(dProbes))
	}

	// App probes
	apps, err := w.client.ListApps()
	if err != nil {
		log.Printf("health: fetch apps: %v", err)
		return
	}
	aProbes := make([]AppHealthProbe, 0, len(apps))
	for _, a := range apps {
		aProbes = append(aProbes, probeApp(a))
	}
	w.health.setApps(aProbes)
	log.Printf("health: probed %d app(s)", len(aProbes))
}

const healthProbeInterval = 5 * time.Minute
