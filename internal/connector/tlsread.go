package connector

import (
	"crypto/tls"
	"fmt"
	"net"
	"time"
)

// tlsReadCert dials host:port over TLS and returns the leaf certificate's
// NotAfter timestamp. This works for any HTTPS management interface — the
// server cert is exposed in the TLS handshake without needing device credentials.
func tlsReadCert(host string, port int, skipVerify bool) (time.Time, error) {
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
		return time.Time{}, fmt.Errorf("tls dial %s: %w", addr, err)
	}
	defer conn.Close()

	certs := conn.ConnectionState().PeerCertificates
	if len(certs) == 0 {
		return time.Time{}, fmt.Errorf("tls dial %s: no certificates in handshake", addr)
	}
	return certs[0].NotAfter, nil
}
