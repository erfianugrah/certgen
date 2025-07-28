package config_test

import (
	"testing"
	"time"

	"github.com/erfianugrah/certgen/pkg/config"
)

func TestNewCertificateConfig(t *testing.T) {
	cfg := config.NewCertificateConfig()

	if cfg == nil {
		t.Fatal("NewCertificateConfig returned nil")
	}

	// Test default values
	tests := []struct {
		name     string
		got      interface{}
		expected interface{}
	}{
		{"Country", cfg.Country, "SG"},
		{"State", cfg.State, "Singapore"},
		{"Locality", cfg.Locality, "Singapore"},
		{"Organization", cfg.Organization, "Erfi Corp"},
		{"OrganizationalUnit", cfg.OrganizationalUnit, "Erfi Proxy"},
		{"ValidityDays", cfg.ValidityDays, 3650},
		{"KeySize", cfg.KeySize, 4096},
		{"PKCS12Password", cfg.PKCS12Password, "yourPKCS12Password"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.expected {
				t.Errorf("%s = %v, want %v", tt.name, tt.got, tt.expected)
			}
		})
	}
}

func TestCertificateConfig_GetRootCAOptions(t *testing.T) {
	cfg := &config.CertificateConfig{
		Domain:             "test.example.com",
		Country:            "US",
		State:              "California",
		Locality:           "San Francisco",
		Organization:       "Test Corp",
		OrganizationalUnit: "IT",
		ValidityDays:       365,
		KeySize:            2048,
	}

	opts := cfg.GetRootCAOptions()

	if opts == nil {
		t.Fatal("GetRootCAOptions returned nil")
	}

	// Test Subject
	if opts.Subject.Country != cfg.Country {
		t.Errorf("Subject.Country = %s, want %s", opts.Subject.Country, cfg.Country)
	}
	if opts.Subject.State != cfg.State {
		t.Errorf("Subject.State = %s, want %s", opts.Subject.State, cfg.State)
	}
	if opts.Subject.Locality != cfg.Locality {
		t.Errorf("Subject.Locality = %s, want %s", opts.Subject.Locality, cfg.Locality)
	}
	if opts.Subject.Organization != cfg.Organization {
		t.Errorf("Subject.Organization = %s, want %s", opts.Subject.Organization, cfg.Organization)
	}
	if opts.Subject.OrganizationalUnit != cfg.OrganizationalUnit {
		t.Errorf("Subject.OrganizationalUnit = %s, want %s", opts.Subject.OrganizationalUnit, cfg.OrganizationalUnit)
	}
	if opts.Subject.CommonName != cfg.Domain {
		t.Errorf("Subject.CommonName = %s, want %s", opts.Subject.CommonName, cfg.Domain)
	}

	// Test DNS Names
	if len(opts.DNSNames) != 1 || opts.DNSNames[0] != cfg.Domain {
		t.Errorf("DNSNames = %v, want [%s]", opts.DNSNames, cfg.Domain)
	}

	// Test CA flag
	if !opts.IsCA {
		t.Error("IsCA = false, want true for Root CA")
	}

	// Test validity period (should be 1024 days for Root CA)
	expectedDuration := 1024 * 24 * time.Hour
	if opts.ValidFor != expectedDuration {
		t.Errorf("ValidFor = %v, want %v", opts.ValidFor, expectedDuration)
	}

	// Test Key Usage
	expectedKeyUsage := []string{"keyCertSign", "cRLSign"}
	if len(opts.KeyUsage) != len(expectedKeyUsage) {
		t.Errorf("KeyUsage length = %d, want %d", len(opts.KeyUsage), len(expectedKeyUsage))
	} else {
		for i, usage := range expectedKeyUsage {
			if opts.KeyUsage[i] != usage {
				t.Errorf("KeyUsage[%d] = %s, want %s", i, opts.KeyUsage[i], usage)
			}
		}
	}
}

func TestCertificateConfig_GetLeafCertOptions(t *testing.T) {
	cfg := &config.CertificateConfig{
		Domain:             "leaf.example.com",
		Country:            "UK",
		State:              "London",
		Locality:           "London",
		Organization:       "UK Corp",
		OrganizationalUnit: "Dev",
		ValidityDays:       90,
		KeySize:            4096,
	}

	opts := cfg.GetLeafCertOptions()

	if opts == nil {
		t.Fatal("GetLeafCertOptions returned nil")
	}

	// Test Subject
	if opts.Subject.Country != cfg.Country {
		t.Errorf("Subject.Country = %s, want %s", opts.Subject.Country, cfg.Country)
	}
	if opts.Subject.CommonName != cfg.Domain {
		t.Errorf("Subject.CommonName = %s, want %s", opts.Subject.CommonName, cfg.Domain)
	}

	// Test CA flag (should be false for leaf cert)
	if opts.IsCA {
		t.Error("IsCA = true, want false for leaf certificate")
	}

	// Test validity period
	expectedDuration := time.Duration(cfg.ValidityDays) * 24 * time.Hour
	if opts.ValidFor != expectedDuration {
		t.Errorf("ValidFor = %v, want %v", opts.ValidFor, expectedDuration)
	}

	// Test Key Usage
	expectedKeyUsage := []string{"digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment"}
	if len(opts.KeyUsage) != len(expectedKeyUsage) {
		t.Errorf("KeyUsage length = %d, want %d", len(opts.KeyUsage), len(expectedKeyUsage))
	}

	// Test Extended Key Usage
	expectedExtKeyUsage := []string{"serverAuth", "clientAuth"}
	if len(opts.ExtKeyUsage) != len(expectedExtKeyUsage) {
		t.Errorf("ExtKeyUsage length = %d, want %d", len(opts.ExtKeyUsage), len(expectedExtKeyUsage))
	}
}

func TestCertificateOptions_ValidFromTime(t *testing.T) {
	cfg := config.NewCertificateConfig()
	cfg.Domain = "time.test.com"

	beforeTime := time.Now()
	opts := cfg.GetRootCAOptions()
	afterTime := time.Now()

	// ValidFrom should be between beforeTime and afterTime
	if opts.ValidFrom.Before(beforeTime) || opts.ValidFrom.After(afterTime) {
		t.Errorf("ValidFrom time is not within expected range")
	}
}
