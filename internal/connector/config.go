package connector

import (
	"fmt"
	"os"
	"time"

	"github.com/certforge/certforge-connector/internal/device"
	"github.com/certforge/certforge-connector/internal/device/audiocodes"
	"gopkg.in/yaml.v3"
)

// Config is loaded from connector.yaml (or the path given via -config flag).
type Config struct {
	CertForgeURL string        `yaml:"certforge_url"` // e.g. https://app.certgovernance.app
	APIKey       string        `yaml:"api_key"`       // cc_... bearer token from CertForge Settings
	PollInterval time.Duration `yaml:"poll_interval"` // default 30s
	Devices      []DeviceConfig `yaml:"devices"`
	PrivateCA    *PrivateCAConfig `yaml:"private_ca"`
}

// PrivateCAConfig enables local CSR signing without a CertForge cloud round-trip.
// Provide the CA certificate and private key files; CertForge is still notified
// for audit and inventory purposes via the ReportCert and MarkDone calls.
type PrivateCAConfig struct {
	CertFile     string `yaml:"cert"`          // path to PEM CA certificate
	KeyFile      string `yaml:"key"`           // path to PEM CA private key
	ValidityDays int    `yaml:"validity_days"` // cert validity; default 365
}

// DeviceConfig holds the on-prem connection details for one network device.
// The ID must match the device ID shown in the CertForge Network Devices page.
type DeviceConfig struct {
	ID         string `yaml:"id"`          // CertForge device ID (UUID)
	Type       string `yaml:"type"`        // audiocodes | ribbon | cisco
	Host       string `yaml:"host"`        // management IP or hostname
	Port       int    `yaml:"port"`        // default 443
	Username   string `yaml:"username"`
	Password   string `yaml:"password"`
	TLSContext int    `yaml:"tls_context"` // default 0
	SkipVerify bool   `yaml:"skip_verify"` // skip TLS cert check on device
}

// NewDevice returns a device.Device driver for this config entry.
// Add new device types here and implement device.Device to support them.
func (d *DeviceConfig) NewDevice() (device.Device, error) {
	switch d.Type {
	case "audiocodes", "":
		return &audiocodes.Client{
			Host:       d.Host,
			Port:       d.Port,
			Username:   d.Username,
			Password:   d.Password,
			TLSContext: d.TLSContext,
			SkipVerify: d.SkipVerify,
		}, nil
	default:
		return nil, fmt.Errorf("unknown device type %q — supported: audiocodes", d.Type)
	}
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("read config %s: %w", path, err)
	}
	data = []byte(os.ExpandEnv(string(data)))

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	if cfg.CertForgeURL == "" {
		return nil, fmt.Errorf("certforge_url is required")
	}
	if cfg.APIKey == "" {
		return nil, fmt.Errorf("api_key is required")
	}
	if cfg.PollInterval == 0 {
		cfg.PollInterval = 30 * time.Second
	}
	// devices: is optional — CertForge is the source of truth for device topology.
	// yaml entries act as credential overrides or connection parameter overrides.
	for i, d := range cfg.Devices {
		if d.ID == "" {
			return nil, fmt.Errorf("device[%d]: id is required when listing devices in yaml", i)
		}
		if cfg.Devices[i].Port == 0 {
			cfg.Devices[i].Port = 443
		}
	}
	return &cfg, nil
}

func (c *Config) DeviceByID(id string) *DeviceConfig {
	for i := range c.Devices {
		if c.Devices[i].ID == id {
			return &c.Devices[i]
		}
	}
	return nil
}
