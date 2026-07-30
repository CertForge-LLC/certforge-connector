// Package device defines the interface that all network device drivers must implement.
// To add a new device type, implement Device and register it in the factory in
// internal/connector/config.go.
package device

import "context"

// Device is the interface each network device driver must implement.
type Device interface {
	// PullCSR retrieves the pending Certificate Signing Request from the device.
	// The device must already have a private key and a self-signed or expired cert;
	// the CSR is generated from that key and returned as a PEM-encoded string.
	PullCSR(ctx context.Context) (csrPEM string, err error)

	// InstallCert pushes a signed PEM certificate to the device, replacing the
	// existing self-signed or expired certificate for the same key.
	InstallCert(ctx context.Context, certPEM string) error
}
