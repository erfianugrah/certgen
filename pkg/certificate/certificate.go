// Package certificate provides functionality for generating X.509 certificates,
// including root CA certificates, leaf certificates, and certificate signing requests.
package certificate

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"fmt"
	"math/big"

	"github.com/erfianugrah/certgen/pkg/config"
)

type Generator struct {
	config *config.CertificateConfig
}

func NewGenerator(cfg *config.CertificateConfig) *Generator {
	return &Generator{
		config: cfg,
	}
}

func (g *Generator) GeneratePrivateKey() (*rsa.PrivateKey, error) {
	if g.config == nil {
		return nil, fmt.Errorf("configuration is nil")
	}
	if g.config.KeySize < 1024 {
		return nil, fmt.Errorf("key size must be at least 1024 bits")
	}
	key, err := rsa.GenerateKey(rand.Reader, g.config.KeySize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate private key: %w", err)
	}
	return key, nil
}

func (g *Generator) GenerateRootCA() (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := g.GeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}

	opts := g.config.GetRootCAOptions()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{opts.Subject.Country},
			Province:           []string{opts.Subject.State},
			Locality:           []string{opts.Subject.Locality},
			Organization:       []string{opts.Subject.Organization},
			OrganizationalUnit: []string{opts.Subject.OrganizationalUnit},
			CommonName:         opts.Subject.CommonName,
		},
		NotBefore:             opts.ValidFrom,
		NotAfter:              opts.ValidFrom.Add(opts.ValidFor),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  true,
		DNSNames:              opts.DNSNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create root CA certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse root CA certificate: %w", err)
	}

	return cert, key, nil
}

func (g *Generator) GenerateLeafCertificate(caCert *x509.Certificate, caKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
	key, err := g.GeneratePrivateKey()
	if err != nil {
		return nil, nil, err
	}

	opts := g.config.GetLeafCertOptions()

	serialNumber, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate serial number: %w", err)
	}

	template := &x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Country:            []string{opts.Subject.Country},
			Province:           []string{opts.Subject.State},
			Locality:           []string{opts.Subject.Locality},
			Organization:       []string{opts.Subject.Organization},
			OrganizationalUnit: []string{opts.Subject.OrganizationalUnit},
			CommonName:         opts.Subject.CommonName,
		},
		NotBefore:   opts.ValidFrom,
		NotAfter:    opts.ValidFrom.Add(opts.ValidFor),
		KeyUsage:    x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth, x509.ExtKeyUsageClientAuth},
		DNSNames:    opts.DNSNames,
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create leaf certificate: %w", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse leaf certificate: %w", err)
	}

	return cert, key, nil
}

func (g *Generator) GenerateCertificateRequest(key *rsa.PrivateKey) (*x509.CertificateRequest, error) {
	opts := g.config.GetLeafCertOptions()

	template := &x509.CertificateRequest{
		Subject: pkix.Name{
			Country:            []string{opts.Subject.Country},
			Province:           []string{opts.Subject.State},
			Locality:           []string{opts.Subject.Locality},
			Organization:       []string{opts.Subject.Organization},
			OrganizationalUnit: []string{opts.Subject.OrganizationalUnit},
			CommonName:         opts.Subject.CommonName,
		},
		DNSNames: opts.DNSNames,
	}

	csrDER, err := x509.CreateCertificateRequest(rand.Reader, template, key)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate request: %w", err)
	}

	csr, err := x509.ParseCertificateRequest(csrDER)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}

	return csr, nil
}
