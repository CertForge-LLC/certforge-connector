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
	"io/fs"
	"log"
	"math/big"
	"os"
	"path/filepath"
	"strings"
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

// ekuShortName maps x509 extended key usage values to their short name strings.
var ekuShortName = map[x509.ExtKeyUsage]string{
	x509.ExtKeyUsageServerAuth:      "serverAuth",
	x509.ExtKeyUsageClientAuth:      "clientAuth",
	x509.ExtKeyUsageCodeSigning:     "codeSigning",
	x509.ExtKeyUsageEmailProtection: "emailProtection",
	x509.ExtKeyUsageTimeStamping:    "timeStamping",
	x509.ExtKeyUsageOCSPSigning:     "OCSPSigning",
}

// ReadRevokedSerials parses a PEM or DER CRL file and returns a set of revoked serial numbers.
// The serial numbers are in the format returned by big.Int.String() (decimal).
func ReadRevokedSerials(crlFile string) (map[string]bool, error) {
	data, err := os.ReadFile(crlFile)
	if err != nil {
		return nil, fmt.Errorf("read CRL %s: %w", crlFile, err)
	}
	var der []byte
	if block, _ := pem.Decode(data); block != nil {
		der = block.Bytes
	} else {
		der = data // assume raw DER
	}
	crl, err := x509.ParseRevocationList(der)
	if err != nil {
		return nil, fmt.Errorf("parse CRL: %w", err)
	}
	revoked := make(map[string]bool, len(crl.RevokedCertificateEntries))
	for _, e := range crl.RevokedCertificateEntries {
		revoked[e.SerialNumber.String()] = true
	}
	return revoked, nil
}

// ScanIssuedCerts walks dir, parses every PEM certificate file found, applies scope
// filters, and returns the matching certs as InventoryCert records ready for push.
// revokedSerials is keyed by decimal serial string; pass nil to skip revocation filtering.
func ScanIssuedCerts(dir string, scope ConnectorScope, revokedSerials map[string]bool) ([]InventoryCert, error) {
	now := time.Now()
	var issuedAfter time.Time
	if scope.IssuedAfter != "" {
		issuedAfter, _ = time.Parse(time.RFC3339, scope.IssuedAfter)
	}

	var out []InventoryCert
	err := filepath.WalkDir(dir, func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil || d.IsDir() {
			return walkErr
		}
		data, err := os.ReadFile(path)
		if err != nil {
			log.Printf("[connector] scan-certs: read %s: %v", path, err)
			return nil
		}
		// A file can contain multiple PEM blocks (e.g. cert + chain).
		rest := data
		for {
			block, remainder := pem.Decode(rest)
			if block == nil {
				break
			}
			rest = remainder
			if block.Type != "CERTIFICATE" {
				continue
			}
			cert, err := x509.ParseCertificate(block.Bytes)
			if err != nil {
				continue
			}

			// Skip scope-excluded certs.
			if !scope.IncludeExpired && cert.NotAfter.Before(now) {
				continue
			}
			if !issuedAfter.IsZero() && cert.NotBefore.Before(issuedAfter) {
				continue
			}
			if !matchesDomainScope(cert, scope.Domains) {
				continue
			}
			if !matchesEKUScope(cert, scope.EKU) {
				continue
			}

			serial := cert.SerialNumber.String()
			if revokedSerials[serial] {
				continue
			}

			ekuList := make([]string, 0, len(cert.ExtKeyUsage))
			for _, e := range cert.ExtKeyUsage {
				if name, ok := ekuShortName[e]; ok {
					ekuList = append(ekuList, name)
				}
			}

			out = append(out, InventoryCert{
				Serial:    serial,
				Issuer:    cert.Issuer.String(),
				Subject:   cert.Subject.CommonName,
				SANs:      cert.DNSNames,
				EKU:       ekuList,
				NotBefore: cert.NotBefore.UTC().Format(time.RFC3339),
				NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
				CertPEM:   string(pem.EncodeToMemory(block)),
				IsCA:      cert.IsCA,
			})
		}
		return nil
	})
	return out, err
}

// matchesDomainScope returns true when patterns is empty (match all) or when the cert's
// CN or any SAN matches at least one pattern (exact or subdomain of pattern).
func matchesDomainScope(cert *x509.Certificate, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	names := append([]string{cert.Subject.CommonName}, cert.DNSNames...)
	for _, pat := range patterns {
		pat = strings.ToLower(pat)
		for _, name := range names {
			name = strings.ToLower(name)
			if name == pat || strings.HasSuffix(name, "."+pat) {
				return true
			}
		}
	}
	return false
}

// matchesEKUScope returns true when patterns is empty (match all) or when the cert
// has at least one EKU from the patterns list.
func matchesEKUScope(cert *x509.Certificate, patterns []string) bool {
	if len(patterns) == 0 {
		return true
	}
	for _, e := range cert.ExtKeyUsage {
		if name, ok := ekuShortName[e]; ok {
			for _, pat := range patterns {
				if pat == name {
					return true
				}
			}
		}
	}
	return false
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
// SignCSR signs the given CSR PEM with this CA.
// validityDays overrides the configured default when > 0; 0 uses the config value.
func (ca *LocalCA) SignCSR(csrPEM string, validityDays int) (string, error) {
	if validityDays <= 0 {
		validityDays = ca.validDays
	}
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
		NotAfter:     now.Add(time.Duration(validityDays) * 24 * time.Hour),
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
