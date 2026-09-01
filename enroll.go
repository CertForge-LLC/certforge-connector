package main

// enroll.go — "certforge-connector enroll" subcommand.
//
// Enrolls this connector with CertForge and writes mTLS credentials (client cert,
// client key, pinned server cert) to local files.  After enrollment, add the file
// paths to certforge-connector.yaml under the mtls_* keys.
//
// Usage:
//
//	certforge-connector enroll \
//	  --token  <one-time enrollment token from CertForge UI>  \
//	  --url    https://app.certgov.app                        \
//	  --label  my-connector                                   \
//	  --out    /etc/certforge-connector

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

func runEnroll(args []string) {
	fs := flag.NewFlagSet("enroll", flag.ExitOnError)
	token := fs.String("token", "", "one-time enrollment token from CertForge UI (required)")
	certforgeURL := fs.String("url", "https://app.certgov.app", "CertForge dashboard URL")
	label := fs.String("label", "connector", "label for this connector in CertForge")
	outDir := fs.String("out", ".", "directory to write credential files into")
	if err := fs.Parse(args); err != nil {
		os.Exit(1)
	}

	if *token == "" {
		fmt.Fprintln(os.Stderr, "error: --token is required")
		fmt.Fprintln(os.Stderr, "  Generate one in CertForge → Settings → Agent Tokens (type: connector)")
		os.Exit(1)
	}

	// 1. Generate ECDSA P-384 key pair.
	fmt.Println("Generating ECDSA P-384 key pair...")
	privateKey, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		log.Fatalf("generate key: %v", err)
	}
	csrTmpl := &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: fmt.Sprintf("connector:%s", *label)},
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, csrTmpl, privateKey)
	if err != nil {
		log.Fatalf("create CSR: %v", err)
	}
	csrPEM := string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}))

	// 2. POST to /v1/agent/enroll on the dashboard port.
	enrollURL := strings.TrimRight(*certforgeURL, "/") + "/v1/agent/enroll"
	fmt.Printf("Enrolling with CertForge at %s...\n", enrollURL)
	payload, _ := json.Marshal(map[string]string{
		"token":      *token,
		"csr_pem":    csrPEM,
		"label":      *label,
		"agent_type": "connector",
	})
	hc := &http.Client{
		Timeout: 30 * time.Second,
		Transport: &http.Transport{
			TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec — bootstrap only; CA pinned after
		},
	}
	resp, err := hc.Post(enrollURL, "application/json", bytes.NewReader(payload))
	if err != nil {
		log.Fatalf("enroll request: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		log.Fatalf("enroll failed (%s): %s", resp.Status, b)
	}

	var result struct {
		CertPEM        string `json:"cert_pem"`
		CAPEM          string `json:"ca_pem"`
		MTLSEndpoint   string `json:"mtls_endpoint"`    // host:port
		MTLSServerCert string `json:"mtls_server_cert"` // pinned server cert PEM
	}
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		log.Fatalf("decode response: %v", err)
	}
	if result.CertPEM == "" {
		log.Fatalf("enrollment response missing cert_pem")
	}

	// 3. Encode client key.
	keyDER, err := x509.MarshalPKCS8PrivateKey(privateKey)
	if err != nil {
		log.Fatalf("marshal key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	// 4. Parse host and port from the returned mTLS endpoint.
	mtlsHost := ""
	mtlsPort := "8443"
	if result.MTLSEndpoint != "" {
		ep := result.MTLSEndpoint
		if i := strings.LastIndex(ep, ":"); i > strings.LastIndex(ep, "]") {
			mtlsPort = ep[i+1:]
			mtlsHost = ep[:i]
		} else {
			mtlsHost = ep
		}
	}

	// 5. Write credential files.
	if err := os.MkdirAll(*outDir, 0o700); err != nil {
		log.Fatalf("create output dir: %v", err)
	}
	certPath := filepath.Join(*outDir, "client.crt")
	keyPath := filepath.Join(*outDir, "client.key")
	caPath := filepath.Join(*outDir, "server.crt")

	if err := os.WriteFile(certPath, []byte(result.CertPEM), 0o600); err != nil {
		log.Fatalf("write %s: %v", certPath, err)
	}
	if err := os.WriteFile(keyPath, keyPEM, 0o600); err != nil {
		log.Fatalf("write %s: %v", keyPath, err)
	}
	if err := os.WriteFile(caPath, []byte(result.MTLSServerCert), 0o600); err != nil {
		log.Fatalf("write %s: %v", caPath, err)
	}

	// 6. Print summary and config snippet.
	certBlock, _ := pem.Decode([]byte(result.CertPEM))
	cert, _ := x509.ParseCertificate(certBlock.Bytes)
	fmt.Println()
	fmt.Println("Enrollment successful!")
	fmt.Printf("  CN:          %s\n", cert.Subject.CommonName)
	if cert != nil {
		fmt.Printf("  Valid until: %s\n", cert.NotAfter.Format("2006-01-02"))
	}
	if result.MTLSEndpoint != "" {
		fmt.Printf("  mTLS endpoint: %s\n", result.MTLSEndpoint)
	}
	fmt.Printf("  Credentials written to: %s\n", *outDir)
	fmt.Println()
	fmt.Println("Create certforge-connector.yaml with the following content:")
	fmt.Println()
	fmt.Printf("  certforge_url: %s\n", strings.TrimRight(*certforgeURL, "/"))
	fmt.Printf("  mtls_host: %s\n", mtlsHost)
	fmt.Printf("  mtls_port: %s\n", mtlsPort)
	fmt.Printf("  mtls_cert: %s\n", certPath)
	fmt.Printf("  mtls_key:  %s\n", keyPath)
	fmt.Printf("  mtls_ca:   %s\n", caPath)
	fmt.Println()
	fmt.Println("api_key is not needed when mTLS is configured.")
}
