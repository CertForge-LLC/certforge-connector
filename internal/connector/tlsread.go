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
// expiry, CN, and DNS SANs. This works for any HTTPS management interface —
// the server cert is exposed in the TLS handshake without needing device credentials.
func tlsReadCert(host string, port int, skipVerify bool) (CertInfo, error) {
	addr := fmt.Sprintf("%s:%d", host, port)
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		addr,
		&tls.Config{
			InsecureSkipVerify: skipVerify, //nolint:gosec
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
