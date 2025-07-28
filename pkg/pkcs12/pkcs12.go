// Package pkcs12 provides functionality for generating PKCS#12 bundles
// containing certificates and private keys. It uses the OpenSSL command-line
// tool as Go's native PKCS#12 encoding support is limited.
package pkcs12

import (
	"crypto/rsa"
	"crypto/x509"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"

	"github.com/erfianugrah/certgen/pkg/encoding"
)

type Generator struct{}

func NewGenerator() *Generator {
	return &Generator{}
}

func (g *Generator) GeneratePKCS12(leafCert *x509.Certificate, leafKey *rsa.PrivateKey, caCert *x509.Certificate, password string) ([]byte, error) {
	// Check if OpenSSL is available
	if _, err := exec.LookPath("openssl"); err != nil {
		return nil, fmt.Errorf("openssl command not found in PATH: %w", err)
	}

	// Create temporary files for the certificates and key
	tempDir, err := os.MkdirTemp("", "certgen")
	if err != nil {
		return nil, fmt.Errorf("failed to create temp dir: %w", err)
	}
	defer os.RemoveAll(tempDir)

	leafCertPath := filepath.Join(tempDir, "leaf.pem")
	leafKeyPath := filepath.Join(tempDir, "leaf.key")
	p12Path := filepath.Join(tempDir, "bundle.p12")

	// Write leaf certificate
	leafCertPEM, err := encoding.EncodeCertificateToPEM(leafCert)
	if err != nil {
		return nil, fmt.Errorf("failed to encode leaf cert: %w", err)
	}
	if err := os.WriteFile(leafCertPath, leafCertPEM, 0644); err != nil {
		return nil, fmt.Errorf("failed to write leaf cert: %w", err)
	}

	// Write leaf key
	leafKeyPEM, err := encoding.EncodePrivateKeyToPEM(leafKey)
	if err != nil {
		return nil, fmt.Errorf("failed to encode leaf key: %w", err)
	}
	if err := os.WriteFile(leafKeyPath, leafKeyPEM, 0600); err != nil {
		return nil, fmt.Errorf("failed to write leaf key: %w", err)
	}

	// Generate PKCS#12 using openssl
	cmd := exec.Command("openssl", "pkcs12", "-export",
		"-out", p12Path,
		"-inkey", leafKeyPath,
		"-in", leafCertPath,
		"-password", fmt.Sprintf("pass:%s", password))

	if err := cmd.Run(); err != nil {
		return nil, fmt.Errorf("failed to generate PKCS#12: %w", err)
	}

	// Read the generated PKCS#12 file
	pfxData, err := os.ReadFile(p12Path)
	if err != nil {
		return nil, fmt.Errorf("failed to read PKCS#12 file: %w", err)
	}

	return pfxData, nil
}

