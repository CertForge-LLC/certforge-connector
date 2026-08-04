package connector

import (
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strings"
	"time"
)

// FetchVaultPKICerts lists all issued certificates from a Vault PKI secrets engine,
// applies scope filters, and returns InventoryCert records ready for push to CertForge.
// Revocation status is read inline from the Vault cert response — no CRL file needed.
func FetchVaultPKICerts(cfg VaultPKIConfig, scope ConnectorScope) ([]InventoryCert, error) {
	token := cfg.Token
	if token == "" {
		token = os.Getenv("VAULT_TOKEN")
	}
	if token == "" {
		return nil, fmt.Errorf("vault_pki: no token - set token in config or VAULT_TOKEN env var")
	}
	mount := cfg.Mount
	if mount == "" {
		mount = "pki"
	}
	addr := strings.TrimRight(cfg.Addr, "/")
	client := &http.Client{Timeout: 30 * time.Second}

	serials, err := vaultListCerts(client, addr, mount, token)
	if err != nil {
		return nil, fmt.Errorf("vault_pki: list certs: %w", err)
	}
	log.Printf("[connector] vault-pki: found %d serials in %s/%s", len(serials), addr, mount)

	now := time.Now()
	var issuedAfter time.Time
	if scope.IssuedAfter != "" {
		issuedAfter, _ = time.Parse(time.RFC3339, scope.IssuedAfter)
	}

	var out []InventoryCert
	for _, serial := range serials {
		certPEM, revoked, err := vaultGetCert(client, addr, mount, token, serial)
		if err != nil {
			log.Printf("[connector] vault-pki: get cert %s: %v", serial, err)
			continue
		}
		if revoked {
			continue
		}

		block, _ := pem.Decode([]byte(certPEM))
		if block == nil {
			continue
		}
		cert, err := x509.ParseCertificate(block.Bytes)
		if err != nil {
			continue
		}

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

		ekuList := make([]string, 0, len(cert.ExtKeyUsage))
		for _, e := range cert.ExtKeyUsage {
			if name, ok := ekuShortName[e]; ok {
				ekuList = append(ekuList, name)
			}
		}

		out = append(out, InventoryCert{
			Serial:    cert.SerialNumber.String(),
			Issuer:    cert.Issuer.String(),
			Subject:   cert.Subject.CommonName,
			SANs:      cert.DNSNames,
			EKU:       ekuList,
			NotBefore: cert.NotBefore.UTC().Format(time.RFC3339),
			NotAfter:  cert.NotAfter.UTC().Format(time.RFC3339),
			CertPEM:   certPEM,
			IsCA:      cert.IsCA,
		})
	}
	return out, nil
}

// vaultListCerts calls LIST /v1/<mount>/certs and returns all serial numbers.
func vaultListCerts(client *http.Client, addr, mount, token string) ([]string, error) {
	url := addr + "/v1/" + mount + "/certs"
	req, err := http.NewRequest("LIST", url, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return nil, fmt.Errorf("LIST %s: %s %s", url, resp.Status, b)
	}
	var body struct {
		Data struct {
			Keys []string `json:"keys"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return nil, err
	}
	return body.Data.Keys, nil
}

// vaultGetCert fetches a single cert by serial and returns its PEM and revocation status.
func vaultGetCert(client *http.Client, addr, mount, token, serial string) (certPEM string, revoked bool, err error) {
	url := addr + "/v1/" + mount + "/cert/" + serial
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return "", false, err
	}
	req.Header.Set("X-Vault-Token", token)
	resp, err := client.Do(req)
	if err != nil {
		return "", false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(io.LimitReader(resp.Body, 4096))
		return "", false, fmt.Errorf("GET %s: %s %s", url, resp.Status, b)
	}
	var body struct {
		Data struct {
			Certificate    string `json:"certificate"`
			RevocationTime int64  `json:"revocation_time"`
		} `json:"data"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		return "", false, err
	}
	return body.Data.Certificate, body.Data.RevocationTime > 0, nil
}
