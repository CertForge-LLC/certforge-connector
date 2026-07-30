package connector

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// CertInfo holds the key fields read from a device's live TLS certificate.
type CertInfo struct {
	NotAfter time.Time
	CN       string
	SANs     []string
}

// tlsReadCert dials host:port over TLS and returns the leaf certificate's
// expiry, CN, and DNS SANs. Verification is always skipped — the purpose is
// to inspect whatever cert the device is presenting, including self-signed,
// expired, or certs without IP SANs. The skipVerify parameter is accepted for
// API compatibility but no longer controls this dial.
func tlsReadCert(host string, port int, skipVerify bool) (CertInfo, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		addr,
		&tls.Config{
			InsecureSkipVerify: true, //nolint:gosec — read-only cert inspection, not auth
			ServerName:         host,
		},
	)
	if err != nil {
		return CertInfo{}, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return CertInfo{}, fmt.Errorf("tls dial %s: no certificates in handshake", addr)
	}
	leaf := certs[0]
	return CertInfo{
		NotAfter: leaf.NotAfter,
		CN:       leaf.Subject.CommonName,
		SANs:     leaf.DNSNames,
	}, nil
}
