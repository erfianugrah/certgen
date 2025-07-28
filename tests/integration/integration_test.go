package integration_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/erfianugrah/certgen/pkg/certificate"
	"github.com/erfianugrah/certgen/pkg/config"
	"github.com/erfianugrah/certgen/pkg/encoding"
	"github.com/erfianugrah/certgen/pkg/fileio"
	"github.com/erfianugrah/certgen/pkg/pkcs12"
)

func TestFullCertificateGeneration(t *testing.T) {
	// Create temp directory for test output
	tempDir, err := os.MkdirTemp("", "certgen_integration_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Change to temp directory
	originalDir, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(originalDir)

	// Configure certificate generation
	cfg := config.NewCertificateConfig()
	cfg.Domain = "integration.test.local"
	cfg.Country = "US"
	cfg.State = "Test State"
	cfg.Locality = "Test City"
	cfg.Organization = "Integration Test Org"
	cfg.OrganizationalUnit = "Test Unit"
	cfg.ValidityDays = 365
	cfg.KeySize = 2048 // Smaller key for faster tests
	cfg.PKCS12Password = "integrationTestPassword"

	// Initialize components
	certGen := certificate.NewGenerator(cfg)
	fileWriter := fileio.NewFileWriter(cfg.Domain)
	pkcs12Gen := pkcs12.NewGenerator()

	// Generate Root CA
	rootCert, rootKey, err := certGen.GenerateRootCA()
	if err != nil {
		t.Fatalf("Failed to generate root CA: %v", err)
	}

	// Save Root CA key
	rootKeyPEM, err := encoding.EncodePrivateKeyToPEM(rootKey)
	if err != nil {
		t.Fatalf("Failed to encode root key: %v", err)
	}
	if err := fileWriter.WriteFile(fileWriter.GetRootKeyPath(), rootKeyPEM); err != nil {
		t.Fatalf("Failed to write root key: %v", err)
	}

	// Save Root CA certificate
	rootCertPEM, err := encoding.EncodeCertificateToPEM(rootCert)
	if err != nil {
		t.Fatalf("Failed to encode root certificate: %v", err)
	}
	if err := fileWriter.WriteFile(fileWriter.GetRootCertPath(), rootCertPEM); err != nil {
		t.Fatalf("Failed to write root certificate: %v", err)
	}

	// Generate leaf certificate
	leafCert, leafKey, err := certGen.GenerateLeafCertificate(rootCert, rootKey)
	if err != nil {
		t.Fatalf("Failed to generate leaf certificate: %v", err)
	}

	// Save leaf key
	leafKeyPEM, err := encoding.EncodePrivateKeyToPEM(leafKey)
	if err != nil {
		t.Fatalf("Failed to encode leaf key: %v", err)
	}
	if err := fileWriter.WriteFile(fileWriter.GetLeafKeyPath(), leafKeyPEM); err != nil {
		t.Fatalf("Failed to write leaf key: %v", err)
	}

	// Save leaf certificate
	leafCertPEM, err := encoding.EncodeCertificateToPEM(leafCert)
	if err != nil {
		t.Fatalf("Failed to encode leaf certificate: %v", err)
	}
	if err := fileWriter.WriteFile(fileWriter.GetLeafCertPath(), leafCertPEM); err != nil {
		t.Fatalf("Failed to write leaf certificate: %v", err)
	}

	// Generate PKCS#12 if OpenSSL is available
	if _, err := os.Stat("/usr/bin/openssl"); err == nil {
		pfxData, err := pkcs12Gen.GeneratePKCS12(leafCert, leafKey, rootCert, cfg.PKCS12Password)
		if err != nil {
			t.Logf("Warning: Failed to generate PKCS#12: %v", err)
		} else {
			if err := fileWriter.WriteFile(fileWriter.GetPKCS12Path(), pfxData); err != nil {
				t.Fatalf("Failed to write PKCS#12: %v", err)
			}
		}
	}

	// Generate Base64 DER files
	leafBase64, err := encoding.ConvertCertificateToBase64DER(leafCert)
	if err != nil {
		t.Fatalf("Failed to convert leaf certificate to base64: %v", err)
	}
	if err := fileWriter.WriteBase64File(fileWriter.GetLeafBase64Path(), leafBase64); err != nil {
		t.Fatalf("Failed to write leaf base64: %v", err)
	}

	rootBase64, err := encoding.ConvertCertificateToBase64DER(rootCert)
	if err != nil {
		t.Fatalf("Failed to convert root certificate to base64: %v", err)
	}
	if err := fileWriter.WriteBase64File(fileWriter.GetRootBase64Path(), rootBase64); err != nil {
		t.Fatalf("Failed to write root base64: %v", err)
	}

	// Verify all files exist
	expectedFiles := []string{
		fileWriter.GetRootKeyPath(),
		fileWriter.GetRootCertPath(),
		fileWriter.GetLeafKeyPath(),
		fileWriter.GetLeafCertPath(),
		fileWriter.GetRootBase64Path(),
		fileWriter.GetLeafBase64Path(),
	}

	for _, file := range expectedFiles {
		if !fileWriter.FileExists(file) {
			t.Errorf("Expected file does not exist: %s", file)
		}
	}

	// Verify we can read back the certificates
	rootCertData, err := fileWriter.ReadFile(fileWriter.GetRootCertPath())
	if err != nil {
		t.Fatalf("Failed to read root certificate: %v", err)
	}

	decodedRootCert, err := encoding.DecodePEMCertificate(rootCertData)
	if err != nil {
		t.Fatalf("Failed to decode root certificate: %v", err)
	}

	if decodedRootCert.Subject.CommonName != cfg.Domain {
		t.Errorf("Decoded root cert CN = %s, want %s", decodedRootCert.Subject.CommonName, cfg.Domain)
	}

	// Verify leaf certificate
	leafCertData, err := fileWriter.ReadFile(fileWriter.GetLeafCertPath())
	if err != nil {
		t.Fatalf("Failed to read leaf certificate: %v", err)
	}

	decodedLeafCert, err := encoding.DecodePEMCertificate(leafCertData)
	if err != nil {
		t.Fatalf("Failed to decode leaf certificate: %v", err)
	}

	// Verify leaf is signed by root
	if err := decodedLeafCert.CheckSignatureFrom(decodedRootCert); err != nil {
		t.Errorf("Leaf certificate signature verification failed: %v", err)
	}
}

func TestMultipleDomainGeneration(t *testing.T) {
	// Create temp directory for test output
	tempDir, err := os.MkdirTemp("", "certgen_multi_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	// Change to temp directory
	originalDir, _ := os.Getwd()
	os.Chdir(tempDir)
	defer os.Chdir(originalDir)

	domains := []string{
		"first.test.local",
		"second.test.local",
		"third.test.local",
	}

	for _, domain := range domains {
		cfg := config.NewCertificateConfig()
		cfg.Domain = domain
		cfg.KeySize = 2048

		certGen := certificate.NewGenerator(cfg)
		fileWriter := fileio.NewFileWriter(cfg.Domain)

		// Generate certificates
		rootCert, rootKey, err := certGen.GenerateRootCA()
		if err != nil {
			t.Fatalf("Failed to generate root CA for %s: %v", domain, err)
		}

		leafCert, leafKey, err := certGen.GenerateLeafCertificate(rootCert, rootKey)
		if err != nil {
			t.Fatalf("Failed to generate leaf certificate for %s: %v", domain, err)
		}

		// Save certificates
		rootCertPEM, _ := encoding.EncodeCertificateToPEM(rootCert)
		leafCertPEM, _ := encoding.EncodeCertificateToPEM(leafCert)
		rootKeyPEM, _ := encoding.EncodePrivateKeyToPEM(rootKey)
		leafKeyPEM, _ := encoding.EncodePrivateKeyToPEM(leafKey)

		if err := fileWriter.WriteFile(fileWriter.GetRootCertPath(), rootCertPEM); err != nil {
			t.Fatalf("Failed to write root cert for %s: %v", domain, err)
		}
		if err := fileWriter.WriteFile(fileWriter.GetLeafCertPath(), leafCertPEM); err != nil {
			t.Fatalf("Failed to write leaf cert for %s: %v", domain, err)
		}
		if err := fileWriter.WriteFile(fileWriter.GetRootKeyPath(), rootKeyPEM); err != nil {
			t.Fatalf("Failed to write root key for %s: %v", domain, err)
		}
		if err := fileWriter.WriteFile(fileWriter.GetLeafKeyPath(), leafKeyPEM); err != nil {
			t.Fatalf("Failed to write leaf key for %s: %v", domain, err)
		}
	}

	// Verify files for each domain exist and are different
	pemFiles, err := filepath.Glob("*.pem")
	if err != nil {
		t.Fatalf("Failed to glob pem files: %v", err)
	}
	keyFiles, err := filepath.Glob("*.key")
	if err != nil {
		t.Fatalf("Failed to glob key files: %v", err)
	}

	files := append(pemFiles, keyFiles...)
	expectedFileCount := len(domains) * 4 // 4 files per domain (2 .pem + 2 .key)
	if len(files) != expectedFileCount {
		t.Errorf("Expected %d files, found %d", expectedFileCount, len(files))
	}

	// Verify each domain has its own files
	for _, domain := range domains {
		prefix := domain[:strings.Index(domain, ".")]
		expectedFiles := []string{
			prefix + "_rootCA.pem",
			prefix + "_rootCA.key",
			prefix + "_leaf.pem",
			prefix + "_leaf.key",
		}

		for _, expectedFile := range expectedFiles {
			found := false
			for _, file := range files {
				if file == expectedFile {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected file %s not found", expectedFile)
			}
		}
	}
}

func TestErrorHandling(t *testing.T) {
	// Test with invalid configuration
	cfg := &config.CertificateConfig{
		Domain:  "error.test.local",
		KeySize: 1024, // Too small for some operations
	}

	certGen := certificate.NewGenerator(cfg)

	// This should still work, even with small key
	_, _, err := certGen.GenerateRootCA()
	if err != nil {
		t.Logf("GenerateRootCA with 1024-bit key failed as expected: %v", err)
	}

	// Test with read-only directory
	if os.Getuid() != 0 { // Skip if running as root
		readOnlyDir, err := os.MkdirTemp("", "readonly_test")
		if err != nil {
			t.Fatalf("Failed to create temp dir: %v", err)
		}
		defer os.RemoveAll(readOnlyDir)

		// Make directory read-only
		os.Chmod(readOnlyDir, 0555)

		fileWriter := fileio.NewFileWriter("readonly.test")
		testPath := filepath.Join(readOnlyDir, "test.pem")

		err = fileWriter.WriteFile(testPath, []byte("test"))
		if err == nil {
			t.Error("WriteFile should fail in read-only directory")
		}
	}
}
