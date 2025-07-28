package pkcs12_test

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/erfianugrah/certgen/pkg/pkcs12"
)

func generateTestCertificates(t *testing.T) (*x509.Certificate, *rsa.PrivateKey, *x509.Certificate, *rsa.PrivateKey) {
	// Generate CA key and certificate
	caKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate CA key: %v", err)
	}

	caTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization: []string{"Test CA"},
			Country:      []string{"US"},
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	caCertDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create CA certificate: %v", err)
	}

	caCert, err := x509.ParseCertificate(caCertDER)
	if err != nil {
		t.Fatalf("Failed to parse CA certificate: %v", err)
	}

	// Generate leaf key and certificate
	leafKey, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate leaf key: %v", err)
	}

	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject: pkix.Name{
			Organization: []string{"Test Leaf"},
			Country:      []string{"US"},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(90 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"test.example.com"},
	}

	leafCertDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCert, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("Failed to create leaf certificate: %v", err)
	}

	leafCert, err := x509.ParseCertificate(leafCertDER)
	if err != nil {
		t.Fatalf("Failed to parse leaf certificate: %v", err)
	}

	return leafCert, leafKey, caCert, caKey
}

func checkOpenSSL(t *testing.T) {
	// Check if OpenSSL is available
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("OpenSSL not found in PATH, skipping test")
	}
}

func TestNewGenerator(t *testing.T) {
	gen := pkcs12.NewGenerator()
	if gen == nil {
		t.Fatal("NewGenerator returned nil")
	}
}

func TestGeneratePKCS12(t *testing.T) {
	checkOpenSSL(t)

	gen := pkcs12.NewGenerator()
	leafCert, leafKey, caCert, _ := generateTestCertificates(t)
	password := "testpassword"

	pfxData, err := gen.GeneratePKCS12(leafCert, leafKey, caCert, password)
	if err != nil {
		t.Fatalf("GeneratePKCS12 failed: %v", err)
	}

	if len(pfxData) == 0 {
		t.Error("GeneratePKCS12 returned empty data")
	}

	// Write to temp file and verify with OpenSSL
	tempFile, err := os.CreateTemp("", "test*.p12")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tempFile.Name())

	if err := os.WriteFile(tempFile.Name(), pfxData, 0644); err != nil {
		t.Fatalf("Failed to write PKCS#12 file: %v", err)
	}

	// Verify with OpenSSL
	cmd := exec.Command("openssl", "pkcs12", "-info", "-in", tempFile.Name(), "-passin", "pass:"+password, "-noout")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Errorf("OpenSSL verification failed: %v\nOutput: %s", err, output)
	}
}

func TestGeneratePKCS12_EmptyPassword(t *testing.T) {
	checkOpenSSL(t)

	gen := pkcs12.NewGenerator()
	leafCert, leafKey, caCert, _ := generateTestCertificates(t)

	// Test with empty password
	pfxData, err := gen.GeneratePKCS12(leafCert, leafKey, caCert, "")
	if err != nil {
		t.Fatalf("GeneratePKCS12 with empty password failed: %v", err)
	}

	if len(pfxData) == 0 {
		t.Error("GeneratePKCS12 returned empty data")
	}
}

func TestGeneratePKCS12_LongPassword(t *testing.T) {
	checkOpenSSL(t)

	gen := pkcs12.NewGenerator()
	leafCert, leafKey, caCert, _ := generateTestCertificates(t)

	// Test with very long password
	longPassword := "this_is_a_very_long_password_that_should_still_work_correctly_1234567890"
	pfxData, err := gen.GeneratePKCS12(leafCert, leafKey, caCert, longPassword)
	if err != nil {
		t.Fatalf("GeneratePKCS12 with long password failed: %v", err)
	}

	if len(pfxData) == 0 {
		t.Error("GeneratePKCS12 returned empty data")
	}
}

func TestGeneratePKCS12_SpecialCharactersPassword(t *testing.T) {
	checkOpenSSL(t)

	gen := pkcs12.NewGenerator()
	leafCert, leafKey, caCert, _ := generateTestCertificates(t)

	// Test with special characters in password
	specialPassword := "p@$$w0rd!#%&*()[]{}|\\:;\"'<>,.?/"
	pfxData, err := gen.GeneratePKCS12(leafCert, leafKey, caCert, specialPassword)
	if err != nil {
		t.Fatalf("GeneratePKCS12 with special characters password failed: %v", err)
	}

	if len(pfxData) == 0 {
		t.Error("GeneratePKCS12 returned empty data")
	}
}

func TestGeneratePKCS12_NilCertificate(t *testing.T) {
	checkOpenSSL(t)

	gen := pkcs12.NewGenerator()
	_, leafKey, caCert, _ := generateTestCertificates(t)

	// This should fail during encoding
	_, err := gen.GeneratePKCS12(nil, leafKey, caCert, "password")
	if err == nil {
		t.Error("GeneratePKCS12 should fail with nil certificate")
	}
}

func TestGeneratePKCS12_NilKey(t *testing.T) {
	checkOpenSSL(t)

	gen := pkcs12.NewGenerator()
	leafCert, _, caCert, _ := generateTestCertificates(t)

	// This should fail during encoding
	_, err := gen.GeneratePKCS12(leafCert, nil, caCert, "password")
	if err == nil {
		t.Error("GeneratePKCS12 should fail with nil key")
	}
}

func TestGeneratePKCS12_NilCACert(t *testing.T) {
	checkOpenSSL(t)

	gen := pkcs12.NewGenerator()
	leafCert, leafKey, _, _ := generateTestCertificates(t)

	// This should still work without CA cert
	pfxData, err := gen.GeneratePKCS12(leafCert, leafKey, nil, "password")
	if err != nil {
		t.Fatalf("GeneratePKCS12 without CA cert failed: %v", err)
	}

	if len(pfxData) == 0 {
		t.Error("GeneratePKCS12 returned empty data")
	}
}

func TestGeneratePKCS12_MultipleCertificates(t *testing.T) {
	checkOpenSSL(t)

	gen := pkcs12.NewGenerator()

	// Generate multiple certificates
	leafCert1, leafKey1, caCert, _ := generateTestCertificates(t)

	// Test with first certificate
	pfxData1, err := gen.GeneratePKCS12(leafCert1, leafKey1, caCert, "password1")
	if err != nil {
		t.Fatalf("First GeneratePKCS12 failed: %v", err)
	}

	// Generate another certificate
	leafCert2, leafKey2, _, _ := generateTestCertificates(t)

	// Test with second certificate
	pfxData2, err := gen.GeneratePKCS12(leafCert2, leafKey2, caCert, "password2")
	if err != nil {
		t.Fatalf("Second GeneratePKCS12 failed: %v", err)
	}

	// Verify both are generated and different
	if len(pfxData1) == 0 || len(pfxData2) == 0 {
		t.Error("GeneratePKCS12 returned empty data")
	}

	if len(pfxData1) == len(pfxData2) {
		// They might still be different even with same length, but very unlikely
		same := true
		for i := range pfxData1 {
			if pfxData1[i] != pfxData2[i] {
				same = false
				break
			}
		}
		if same {
			t.Error("Two different certificates produced identical PKCS#12 data")
		}
	}
}
