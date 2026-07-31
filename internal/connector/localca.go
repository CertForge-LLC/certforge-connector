package connector

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"os"
	"time"
)

// LocalCA holds a loaded CA certificate and private key for signing device CSRs.
type LocalCA struct {
	cert       *x509.Certificate
	key        crypto.Signer
	validDays  int
}

// LoadLocalCA loads a CA certificate and private key from PEM files.
func LoadLocalCA(cfg PrivateCAConfig) (*LocalCA, error) {
	certPEM, err := os.ReadFile(cfg.CertFile)
	if err != nil {
		return nil, fmt.Errorf("private_ca: read cert %s: %w", cfg.CertFile, err)
	}
	keyPEM, err := os.ReadFile(cfg.KeyFile)
	if err != nil {
		return nil, fmt.Errorf("private_ca: read key %s: %w", cfg.KeyFile, err)
	}

	tlsCert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return nil, fmt.Errorf("private_ca: load cert/key pair: %w", err)
	}
	caCert, err := x509.ParseCertificate(tlsCert.Certificate[0])
	if err != nil {
		return nil, fmt.Errorf("private_ca: parse cert: %w", err)
	}
	if !caCert.IsCA {
		return nil, fmt.Errorf("private_ca: certificate is not a CA (IsCA=false)")
	}

	var signer crypto.Signer
	switch k := tlsCert.PrivateKey.(type) {
	case *rsa.PrivateKey:
		signer = k
	case *ecdsa.PrivateKey:
		signer = k
	default:
		return nil, fmt.Errorf("private_ca: unsupported key type %T", tlsCert.PrivateKey)
	}

	days := cfg.ValidityDays
	if days <= 0 {
		days = 365
	}
	return &LocalCA{cert: caCert, key: signer, validDays: days}, nil
}

// parseCertPEM parses a PEM certificate and returns a CertInfo for reporting.
func parseCertPEM(certPEM string) (CertInfo, error) {
	block, _ := pem.Decode([]byte(certPEM))
	if block == nil {
		return CertInfo{}, fmt.Errorf("no PEM block in certificate")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return CertInfo{}, err
	}
	info := CertInfo{
		CN:       cert.Subject.CommonName,
		NotAfter: cert.NotAfter,
		SANs:     cert.DNSNames,
	}
	return info, nil
}

// SignCSR signs a PEM-encoded CSR and returns a PEM-encoded certificate.
func (ca *LocalCA) SignCSR(csrPEM string) (string, error) {
	block, _ := pem.Decode([]byte(csrPEM))
	if block == nil {
		return "", fmt.Errorf("local CA: no PEM block found in CSR")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return "", fmt.Errorf("local CA: parse CSR: %w", err)
	}
	if err := csr.CheckSignature(); err != nil {
		return "", fmt.Errorf("local CA: CSR signature invalid: %w", err)
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return "", fmt.Errorf("local CA: generate serial: %w", err)
	}

	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: csr.Subject.CommonName, Organization: csr.Subject.Organization},
		NotBefore:    now.Add(-1 * time.Minute), // small back-date to handle clock skew
		NotAfter:     now.Add(time.Duration(ca.validDays) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     csr.DNSNames,
		IPAddresses:  csr.IPAddresses,
		EmailAddresses: csr.EmailAddresses,
	}

	der, err := x509.CreateCertificate(rand.Reader, template, ca.cert, csr.PublicKey, ca.key)
	if err != nil {
		return "", fmt.Errorf("local CA: sign: %w", err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})), nil
}
