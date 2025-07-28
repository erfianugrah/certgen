package encoding_test

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/pem"
	"math/big"
	"testing"
	"time"

	"github.com/erfianugrah/certgen/pkg/encoding"
)

func generateTestCertificate(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("Failed to generate key: %v", err)
	}

	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject: pkix.Name{
			Organization:  []string{"Test Org"},
			Country:       []string{"US"},
			Province:      []string{""},
			Locality:      []string{""},
			StreetAddress: []string{""},
			PostalCode:    []string{""},
		},
		NotBefore:   time.Now(),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{"test.example.com"},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("Failed to create certificate: %v", err)
	}

	cert, err := x509.ParseCertificate(certDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate: %v", err)
	}

	return cert, key
}

func TestEncodeCertificateToPEM(t *testing.T) {
	cert, _ := generateTestCertificate(t)

	pemData, err := encoding.EncodeCertificateToPEM(cert)
	if err != nil {
		t.Fatalf("EncodeCertificateToPEM failed: %v", err)
	}

	if len(pemData) == 0 {
		t.Error("EncodeCertificateToPEM returned empty data")
	}

	// Verify it's valid PEM
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}

	if block.Type != "CERTIFICATE" {
		t.Errorf("PEM block type = %s, want CERTIFICATE", block.Type)
	}

	// Verify the certificate data matches
	if !bytes.Equal(block.Bytes, cert.Raw) {
		t.Error("PEM block bytes don't match certificate raw data")
	}
}

func TestEncodePrivateKeyToPEM(t *testing.T) {
	_, key := generateTestCertificate(t)

	pemData, err := encoding.EncodePrivateKeyToPEM(key)
	if err != nil {
		t.Fatalf("EncodePrivateKeyToPEM failed: %v", err)
	}

	if len(pemData) == 0 {
		t.Error("EncodePrivateKeyToPEM returned empty data")
	}

	// Verify it's valid PEM
	block, _ := pem.Decode(pemData)
	if block == nil {
		t.Fatal("Failed to decode PEM block")
	}

	if block.Type != "PRIVATE KEY" {
		t.Errorf("PEM block type = %s, want PRIVATE KEY", block.Type)
	}

	// Verify we can parse the key back
	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		t.Errorf("Failed to parse private key from PEM: %v", err)
	}

	rsaKey, ok := parsedKey.(*rsa.PrivateKey)
	if !ok {
		t.Error("Parsed key is not an RSA private key")
	}

	// Verify key properties match
	if rsaKey.N.Cmp(key.N) != 0 {
		t.Error("Parsed key N doesn't match original")
	}
}

func TestConvertPEMToDER(t *testing.T) {
	cert, _ := generateTestCertificate(t)

	pemData, _ := encoding.EncodeCertificateToPEM(cert)

	derData, err := encoding.ConvertPEMToDER(pemData)
	if err != nil {
		t.Fatalf("ConvertPEMToDER failed: %v", err)
	}

	if !bytes.Equal(derData, cert.Raw) {
		t.Error("DER data doesn't match original certificate")
	}
}

func TestConvertPEMToDER_InvalidPEM(t *testing.T) {
	invalidPEM := []byte("not a valid PEM")

	_, err := encoding.ConvertPEMToDER(invalidPEM)
	if err == nil {
		t.Error("ConvertPEMToDER should fail with invalid PEM")
	}
}

func TestEncodeDERToBase64(t *testing.T) {
	testData := []byte("test DER data")

	base64Data := encoding.EncodeDERToBase64(testData)

	// Verify it's valid base64
	decoded, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		t.Errorf("Failed to decode base64: %v", err)
	}

	if !bytes.Equal(decoded, testData) {
		t.Error("Decoded data doesn't match original")
	}
}

func TestConvertCertificateToBase64DER(t *testing.T) {
	cert, _ := generateTestCertificate(t)

	base64Data, err := encoding.ConvertCertificateToBase64DER(cert)
	if err != nil {
		t.Fatalf("ConvertCertificateToBase64DER failed: %v", err)
	}

	// Decode and verify
	derData, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		t.Errorf("Failed to decode base64: %v", err)
	}

	if !bytes.Equal(derData, cert.Raw) {
		t.Error("Decoded DER doesn't match certificate raw data")
	}
}

func TestDecodePEMCertificate(t *testing.T) {
	cert, _ := generateTestCertificate(t)
	pemData, _ := encoding.EncodeCertificateToPEM(cert)

	decodedCert, err := encoding.DecodePEMCertificate(pemData)
	if err != nil {
		t.Fatalf("DecodePEMCertificate failed: %v", err)
	}

	if decodedCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("Decoded certificate serial number doesn't match")
	}

	if decodedCert.Subject.Organization[0] != cert.Subject.Organization[0] {
		t.Error("Decoded certificate organization doesn't match")
	}
}

func TestDecodePEMCertificate_InvalidPEM(t *testing.T) {
	tests := []struct {
		name    string
		pemData []byte
	}{
		{"Invalid PEM", []byte("not a valid PEM")},
		{"Wrong type PEM", []byte(`-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
-----END PRIVATE KEY-----`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encoding.DecodePEMCertificate(tt.pemData)
			if err == nil {
				t.Error("DecodePEMCertificate should fail with invalid input")
			}
		})
	}
}

func TestDecodePEMPrivateKey(t *testing.T) {
	_, key := generateTestCertificate(t)
	pemData, _ := encoding.EncodePrivateKeyToPEM(key)

	decodedKey, err := encoding.DecodePEMPrivateKey(pemData)
	if err != nil {
		t.Fatalf("DecodePEMPrivateKey failed: %v", err)
	}

	if decodedKey.N.Cmp(key.N) != 0 {
		t.Error("Decoded key N doesn't match original")
	}

	if decodedKey.E != key.E {
		t.Error("Decoded key E doesn't match original")
	}
}

func TestDecodePEMPrivateKey_InvalidPEM(t *testing.T) {
	tests := []struct {
		name    string
		pemData []byte
	}{
		{"Invalid PEM", []byte("not a valid PEM")},
		{"Wrong type PEM", []byte(`-----BEGIN CERTIFICATE-----
MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
-----END CERTIFICATE-----`)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := encoding.DecodePEMPrivateKey(tt.pemData)
			if err == nil {
				t.Error("DecodePEMPrivateKey should fail with invalid input")
			}
		})
	}
}

func TestRoundTripCertificate(t *testing.T) {
	// Test full round trip: cert -> PEM -> DER -> Base64 and back
	cert, _ := generateTestCertificate(t)

	// Encode to PEM
	pemData, err := encoding.EncodeCertificateToPEM(cert)
	if err != nil {
		t.Fatalf("Failed to encode to PEM: %v", err)
	}

	// Convert PEM to DER
	derData, err := encoding.ConvertPEMToDER(pemData)
	if err != nil {
		t.Fatalf("Failed to convert PEM to DER: %v", err)
	}

	// Encode DER to Base64
	base64Data := encoding.EncodeDERToBase64(derData)

	// Decode Base64 back to DER
	decodedDER, err := base64.StdEncoding.DecodeString(base64Data)
	if err != nil {
		t.Fatalf("Failed to decode base64: %v", err)
	}

	// Parse DER back to certificate
	parsedCert, err := x509.ParseCertificate(decodedDER)
	if err != nil {
		t.Fatalf("Failed to parse certificate from DER: %v", err)
	}

	// Verify certificates match
	if parsedCert.SerialNumber.Cmp(cert.SerialNumber) != 0 {
		t.Error("Round trip certificate serial number doesn't match")
	}
}
