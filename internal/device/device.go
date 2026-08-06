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

// CSRGenerator is an optional interface for device drivers that can trigger the
// device to generate a new key pair and CSR on demand. When implemented, the
// connector calls GenerateCSR before PullCSR so the full renewal is hands-off.
// cn is the desired Common Name (typically the device hostname).
type CSRGenerator interface {
	GenerateCSR(ctx context.Context, cn string) error
}
