package certificate_test

import (
	"crypto/x509"
	"testing"
	"time"

	"github.com/erfianugrah/certgen/pkg/certificate"
	"github.com/erfianugrah/certgen/pkg/config"
)

func TestNewGenerator(t *testing.T) {
	cfg := &config.CertificateConfig{
		Domain:  "test.example.com",
		KeySize: 2048,
	}

	gen := certificate.NewGenerator(cfg)
	if gen == nil {
		t.Fatal("NewGenerator returned nil")
	}
}

func TestGenerator_GeneratePrivateKey(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
	}{
		{"2048-bit key", 2048},
		{"4096-bit key", 4096},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.CertificateConfig{
				Domain:  "test.example.com",
				KeySize: tt.keySize,
			}
			gen := certificate.NewGenerator(cfg)

			key, err := gen.GeneratePrivateKey()
			if err != nil {
				t.Fatalf("GeneratePrivateKey failed: %v", err)
			}

			if key == nil {
				t.Fatal("GeneratePrivateKey returned nil key")
			}

			// Verify key size
			if key.N.BitLen() != tt.keySize {
				t.Errorf("Key size = %d bits, want %d bits", key.N.BitLen(), tt.keySize)
			}

			// Verify key is valid
			if err := key.Validate(); err != nil {
				t.Errorf("Generated key is invalid: %v", err)
			}
		})
	}
}

func TestGenerator_GenerateRootCA(t *testing.T) {
	cfg := config.NewCertificateConfig()
	cfg.Domain = "ca.example.com"
	cfg.Country = "US"
	cfg.State = "California"
	cfg.Locality = "San Francisco"
	cfg.Organization = "Test CA Org"
	cfg.OrganizationalUnit = "CA Unit"
	cfg.KeySize = 2048 // Use smaller key for faster tests

	gen := certificate.NewGenerator(cfg)

	cert, key, err := gen.GenerateRootCA()
	if err != nil {
		t.Fatalf("GenerateRootCA failed: %v", err)
	}

	if cert == nil {
		t.Fatal("GenerateRootCA returned nil certificate")
	}
	if key == nil {
		t.Fatal("GenerateRootCA returned nil key")
	}

	// Verify certificate properties
	if !cert.IsCA {
		t.Error("Root CA certificate IsCA = false, want true")
	}

	if cert.Subject.CommonName != cfg.Domain {
		t.Errorf("Certificate CN = %s, want %s", cert.Subject.CommonName, cfg.Domain)
	}

	if len(cert.Subject.Country) == 0 || cert.Subject.Country[0] != cfg.Country {
		t.Errorf("Certificate Country = %v, want [%s]", cert.Subject.Country, cfg.Country)
	}

	if len(cert.Subject.Organization) == 0 || cert.Subject.Organization[0] != cfg.Organization {
		t.Errorf("Certificate Organization = %v, want [%s]", cert.Subject.Organization, cfg.Organization)
	}

	// Verify key usage
	expectedKeyUsage := x509.KeyUsageCertSign | x509.KeyUsageCRLSign
	if cert.KeyUsage != expectedKeyUsage {
		t.Errorf("KeyUsage = %v, want %v", cert.KeyUsage, expectedKeyUsage)
	}

	// Verify DNS names
	if len(cert.DNSNames) != 1 || cert.DNSNames[0] != cfg.Domain {
		t.Errorf("DNSNames = %v, want [%s]", cert.DNSNames, cfg.Domain)
	}

	// Verify serial number is generated (not predictable)
	if cert.SerialNumber == nil || cert.SerialNumber.BitLen() == 0 {
		t.Error("SerialNumber was not properly generated")
	}

	// Verify validity period
	expectedNotAfter := cert.NotBefore.Add(1024 * 24 * time.Hour)
	if !cert.NotAfter.Equal(expectedNotAfter) {
		t.Errorf("NotAfter = %v, want %v", cert.NotAfter, expectedNotAfter)
	}

	// Verify self-signed
	if err := cert.CheckSignatureFrom(cert); err != nil {
		t.Errorf("Root CA is not properly self-signed: %v", err)
	}
}

func TestGenerator_GenerateLeafCertificate(t *testing.T) {
	cfg := config.NewCertificateConfig()
	cfg.Domain = "leaf.example.com"
	cfg.ValidityDays = 90
	cfg.KeySize = 2048

	gen := certificate.NewGenerator(cfg)

	// First generate CA
	caCert, caKey, err := gen.GenerateRootCA()
	if err != nil {
		t.Fatalf("Failed to generate CA: %v", err)
	}

	// Generate leaf certificate
	leafCert, leafKey, err := gen.GenerateLeafCertificate(caCert, caKey)
	if err != nil {
		t.Fatalf("GenerateLeafCertificate failed: %v", err)
	}

	if leafCert == nil {
		t.Fatal("GenerateLeafCertificate returned nil certificate")
	}
	if leafKey == nil {
		t.Fatal("GenerateLeafCertificate returned nil key")
	}

	// Verify certificate properties
	if leafCert.IsCA {
		t.Error("Leaf certificate IsCA = true, want false")
	}

	if leafCert.Subject.CommonName != cfg.Domain {
		t.Errorf("Certificate CN = %s, want %s", leafCert.Subject.CommonName, cfg.Domain)
	}

	// Verify key usage
	expectedKeyUsage := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if leafCert.KeyUsage != expectedKeyUsage {
		t.Errorf("KeyUsage = %v, want %v", leafCert.KeyUsage, expectedKeyUsage)
	}

	// Verify extended key usage
	if len(leafCert.ExtKeyUsage) != 2 {
		t.Errorf("ExtKeyUsage length = %d, want 2", len(leafCert.ExtKeyUsage))
	} else {
		hasServerAuth := false
		hasClientAuth := false
		for _, usage := range leafCert.ExtKeyUsage {
			if usage == x509.ExtKeyUsageServerAuth {
				hasServerAuth = true
			}
			if usage == x509.ExtKeyUsageClientAuth {
				hasClientAuth = true
			}
		}
		if !hasServerAuth {
			t.Error("Leaf certificate missing ServerAuth extended key usage")
		}
		if !hasClientAuth {
			t.Error("Leaf certificate missing ClientAuth extended key usage")
		}
	}

	// Verify DNS names
	if len(leafCert.DNSNames) != 1 || leafCert.DNSNames[0] != cfg.Domain {
		t.Errorf("DNSNames = %v, want [%s]", leafCert.DNSNames, cfg.Domain)
	}

	// Verify validity period
	expectedDuration := time.Duration(cfg.ValidityDays) * 24 * time.Hour
	actualDuration := leafCert.NotAfter.Sub(leafCert.NotBefore)
	// Allow small time difference due to execution time
	if actualDuration < expectedDuration-time.Minute || actualDuration > expectedDuration+time.Minute {
		t.Errorf("Certificate validity = %v, want ~%v", actualDuration, expectedDuration)
	}

	// Verify certificate is signed by CA
	if err := leafCert.CheckSignatureFrom(caCert); err != nil {
		t.Errorf("Leaf certificate signature verification failed: %v", err)
	}

	// Verify serial number is generated
	if leafCert.SerialNumber == nil || leafCert.SerialNumber.BitLen() == 0 {
		t.Error("Leaf certificate serial number was not properly generated")
	}
}

func TestGenerator_GenerateCertificateRequest(t *testing.T) {
	cfg := config.NewCertificateConfig()
	cfg.Domain = "csr.example.com"
	cfg.Country = "CA"
	cfg.State = "Ontario"
	cfg.Locality = "Toronto"
	cfg.Organization = "CSR Test Org"
	cfg.OrganizationalUnit = "CSR Unit"
	cfg.KeySize = 2048

	gen := certificate.NewGenerator(cfg)

	key, err := gen.GeneratePrivateKey()
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	csr, err := gen.GenerateCertificateRequest(key)
	if err != nil {
		t.Fatalf("GenerateCertificateRequest failed: %v", err)
	}

	if csr == nil {
		t.Fatal("GenerateCertificateRequest returned nil")
	}

	// Verify CSR properties
	if csr.Subject.CommonName != cfg.Domain {
		t.Errorf("CSR CN = %s, want %s", csr.Subject.CommonName, cfg.Domain)
	}

	if len(csr.Subject.Country) == 0 || csr.Subject.Country[0] != cfg.Country {
		t.Errorf("CSR Country = %v, want [%s]", csr.Subject.Country, cfg.Country)
	}

	if len(csr.DNSNames) != 1 || csr.DNSNames[0] != cfg.Domain {
		t.Errorf("CSR DNSNames = %v, want [%s]", csr.DNSNames, cfg.Domain)
	}

	// Verify CSR signature
	if err := csr.CheckSignature(); err != nil {
		t.Errorf("CSR signature verification failed: %v", err)
	}
}

func TestGenerator_MultipleCertificates(t *testing.T) {
	cfg := config.NewCertificateConfig()
	cfg.Domain = "multi.example.com"
	cfg.KeySize = 2048

	gen := certificate.NewGenerator(cfg)

	// Generate multiple certificates
	certs := make([]*x509.Certificate, 3)
	keys := make([]*x509.Certificate, 3)

	for i := 0; i < 3; i++ {
		cert, key, err := gen.GenerateRootCA()
		if err != nil {
			t.Fatalf("Failed to generate certificate %d: %v", i, err)
		}
		certs[i] = cert
		keys[i] = cert

		// Verify each has unique serial number
		for j := 0; j < i; j++ {
			if certs[i].SerialNumber.Cmp(certs[j].SerialNumber) == 0 {
				t.Errorf("Certificates %d and %d have same serial number", i, j)
			}
		}

		// Verify public keys are different
		if i > 0 && cert.PublicKey == key.PublicKey {
			t.Errorf("Certificate %d has same public key as previous", i)
		}
	}
}

func TestGenerator_NilConfig(t *testing.T) {
	// This should not panic
	gen := certificate.NewGenerator(nil)
	if gen == nil {
		t.Fatal("NewGenerator with nil config returned nil")
	}

	// Operations should fail gracefully
	_, err := gen.GeneratePrivateKey()
	if err == nil {
		t.Error("GeneratePrivateKey should fail with nil config")
	}
}

func TestGenerator_InvalidKeySize(t *testing.T) {
	tests := []struct {
		name    string
		keySize int
	}{
		{"Zero key size", 0},
		{"Too small key size", 512},
		{"Negative key size", -1024},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &config.CertificateConfig{
				Domain:  "test.example.com",
				KeySize: tt.keySize,
			}
			gen := certificate.NewGenerator(cfg)

			_, err := gen.GeneratePrivateKey()
			if err == nil {
				t.Errorf("GeneratePrivateKey should fail with key size %d", tt.keySize)
			}
		})
	}
}

func TestGenerator_EmptyDomain(t *testing.T) {
	cfg := config.NewCertificateConfig()
	cfg.Domain = "" // Empty domain
	cfg.KeySize = 2048

	gen := certificate.NewGenerator(cfg)

	cert, _, err := gen.GenerateRootCA()
	if err != nil {
		t.Fatalf("GenerateRootCA failed with empty domain: %v", err)
	}

	// Should still generate certificate with empty CN
	if cert.Subject.CommonName != "" {
		t.Errorf("Certificate CN = %s, want empty", cert.Subject.CommonName)
	}
}

func TestGenerator_SpecialCharacterDomain(t *testing.T) {
	specialDomains := []string{
		"test-with-dash.example.com",
		"test_with_underscore.example.com",
		"123numeric.example.com",
		"*.wildcard.example.com",
	}

	for _, domain := range specialDomains {
		t.Run(domain, func(t *testing.T) {
			cfg := config.NewCertificateConfig()
			cfg.Domain = domain
			cfg.KeySize = 2048

			gen := certificate.NewGenerator(cfg)

			cert, _, err := gen.GenerateRootCA()
			if err != nil {
				t.Fatalf("GenerateRootCA failed for domain %s: %v", domain, err)
			}

			if cert.Subject.CommonName != domain {
				t.Errorf("Certificate CN = %s, want %s", cert.Subject.CommonName, domain)
			}

			if len(cert.DNSNames) != 1 || cert.DNSNames[0] != domain {
				t.Errorf("DNSNames = %v, want [%s]", cert.DNSNames, domain)
			}
		})
	}
}