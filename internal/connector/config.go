package connector

import (
	"fmt"
	"os"
	"time"

	"github.com/certforge/certforge-connector/internal/device"
	"github.com/certforge/certforge-connector/internal/device/audiocodes"
	"github.com/certforge/certforge-connector/internal/device/f5"
	"gopkg.in/yaml.v3"
)

// Config is loaded from connector.yaml (or the path given via -config flag).
type Config struct {
	CertForgeURL string            `yaml:"certforge_url"` // e.g. https://app.certgovernance.app
	APIKey       string            `yaml:"api_key"`       // cc_... bearer token from CertForge Settings
	ConnectorID  string            `yaml:"connector_id"`  // ID of this connector's record in CertForge (Settings -> CA Connectors)
	PollInterval time.Duration     `yaml:"poll_interval"` // default 30s
	Devices      []DeviceConfig    `yaml:"devices"`
	PrivateCA    *PrivateCAConfig  `yaml:"private_ca"`  // single CA (backward compat)
	PrivateCAs   []PrivateCAConfig `yaml:"private_cas"` // multiple CAs (use when managing several PKI mounts)
}

// PrivateCAConfig enables local CSR signing without a CertForge cloud round-trip.
// Provide the CA certificate and private key files; CertForge is still notified
// for audit and inventory purposes via the ReportCert and MarkDone calls.
//
// To enable full inventory sync (like a CA connector), set ca_connector_id and
// either issued_certs_dir (file-based CAs like OpenSSL/Easy-RSA) or vault_pki
// (HashiCorp Vault PKI secrets engine). The agent pushes all issued certs to
// CertForge so they appear in the discovery inventory as tracked.
type PrivateCAConfig struct {
	CertFile       string          `yaml:"cert"`             // path to PEM CA certificate
	KeyFile        string          `yaml:"key"`              // path to PEM CA private key
	ValidityDays   int             `yaml:"validity_days"`    // cert validity; default 365
	CAConnectorID  string          `yaml:"ca_connector_id"`  // CertForge CA connector record ID for inventory push
	IssuedCertsDir string          `yaml:"issued_certs_dir"` // directory of PEM cert files to sync as inventory
	CRLFile        string          `yaml:"crl_file"`         // optional CRL PEM; revoked certs are excluded from inventory
	VaultPKI       *VaultPKIConfig `yaml:"vault_pki"`        // Vault PKI secrets engine (alternative to issued_certs_dir)
}

// VaultPKIConfig points the agent at a HashiCorp Vault PKI secrets engine.
// The agent lists all issued serials and fetches each cert; revocation status
// is read inline from the Vault response (no separate CRL file needed).
// When a CA connector is configured in CertForge, vault config is delivered via
// the server API and YAML fields are optional overrides.
type VaultPKIConfig struct {
	Addr  string `yaml:"addr"  json:"addr"`  // Vault address, e.g. https://vault.example.com
	Token string `yaml:"token" json:"token"` // Vault token; falls back to $VAULT_TOKEN if empty
	Mount string `yaml:"mount" json:"mount"` // PKI secrets engine mount path; default "pki"
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

// SupportedDeviceTypes returns the list of device driver types this connector binary supports.
// Update this alongside the switch in NewDevice whenever a new driver is added.
func SupportedDeviceTypes() []string {
	return []string{"audiocodes", "f5"}
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
	case "f5":
		return &f5.Client{
			Host:       d.Host,
			Port:       d.Port,
			Username:   d.Username,
			Password:   d.Password,
			TLSContext: d.TLSContext,
			SkipVerify: d.SkipVerify,
		}, nil
	default:
		return nil, fmt.Errorf("unknown device type %q - supported: audiocodes, f5", d.Type)
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
