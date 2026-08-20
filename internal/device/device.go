// Package device defines the interface that all network device drivers must implement.
// To add a new device type, implement Device and register it in the factory in
// internal/connector/config.go.
package device

import "context"

// Device is the interface each network device driver must implement.
type Device interface {
	// PullCSR retrieves the pending Certificate Signing Request from the device.
	PullCSR(ctx context.Context) (csrPEM string, err error)

	// InstallCert pushes a signed PEM certificate to the device, replacing the
	// existing self-signed or expired certificate for the same key.
	InstallCert(ctx context.Context, certPEM string) error
}

// Versioned is an optional interface that device drivers may implement to report
// their current software or firmware version. The connector queries this during
// job execution when credentials are already available.
type Versioned interface {
	SoftwareVersion(ctx context.Context) (string, error)
}

// CertSubject holds the certificate subject fields sent to the device for CSR generation.
type CertSubject struct {
	CN   string   // Common Name (FQDN or hostname)
	SANs []string // DNS Subject Alternative Names; should include CN when using ACME CAs
	O    string   // Organization
	OU   string   // Organizational Unit
	L    string   // Locality / City
	ST   string   // State / Province
	C    string   // Country Code (2-letter ISO)
}

// CSRGenerator is an optional interface for device drivers that can generate a
// new key pair and CSR on the device in a single API call. When implemented,
// the connector calls GenerateCSR instead of PullCSR so no pre-existing key
// or CSR is required on the device.
type CSRGenerator interface {
	GenerateCSR(ctx context.Context, subject CertSubject) (csrPEM string, err error)
}

// TrustedRootInstaller is an optional interface for device drivers that support
// adding CA certificates to the device's trusted root store. The connector calls
// this after InstallCert to push the signing chain so the device trusts its peers.
type TrustedRootInstaller interface {
	InstallTrustedRoot(ctx context.Context, caPEM string) error
}

// PrivateKeyInstaller is an optional interface for device drivers that accept
// an externally-generated private key. When a device implements this alongside
// CSRGenerator, the connector can generate its own key+CSR with DNS SANs
// for submission to ACME CAs, then push the key and signed cert together.
type PrivateKeyInstaller interface {
	InstallPrivateKey(ctx context.Context, keyPEM string) error
}

// ConfigSaver is an optional interface for device drivers that require an
// explicit "save configuration" call after certificate installation. Devices
// that don't implement this interface apply changes immediately without a
// separate save step.
type ConfigSaver interface {
	SaveConfiguration(ctx context.Context) error
}

// CertInfo holds the parsed details of a certificate read from a device.
type CertInfo struct {
	CN      string
	SANs    []string
	NotAfter  string // RFC3339
}

// CertReader is an optional interface for device drivers that can read their
// currently-installed certificate via API rather than a raw TLS dial. When
// implemented, the connector calls ReadCert instead of TLS-dialing the device
// host:port, which is useful when the management port presents a different cert
// than the one being managed (e.g. F5 iControl REST on 8443 vs an LTM profile).
type CertReader interface {
	ReadCert(ctx context.Context) (*CertInfo, error)
}
