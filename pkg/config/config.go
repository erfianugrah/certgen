// Package config defines certificate configuration structures and provides
// default values for certificate generation.
package config

import (
	"time"
)

type CertificateConfig struct {
	Domain             string
	Country            string
	State              string
	Locality           string
	Organization       string
	OrganizationalUnit string
	ValidityDays       int
	KeySize            int
	PKCS12Password     string
}

type Subject struct {
	Country            string
	State              string
	Locality           string
	Organization       string
	OrganizationalUnit string
	CommonName         string
}

type CertificateOptions struct {
	Subject     Subject
	DNSNames    []string
	ValidFrom   time.Time
	ValidFor    time.Duration
	IsCA        bool
	KeyUsage    []string
	ExtKeyUsage []string
}

func NewCertificateConfig() *CertificateConfig {
	return &CertificateConfig{
		Country:            "SG",
		State:              "Singapore",
		Locality:           "Singapore",
		Organization:       "Erfi Corp",
		OrganizationalUnit: "Erfi Proxy",
		ValidityDays:       3650,
		KeySize:            4096,
		PKCS12Password:     "yourPKCS12Password",
	}
}

func (c *CertificateConfig) GetRootCAOptions() *CertificateOptions {
	return &CertificateOptions{
		Subject: Subject{
			Country:            c.Country,
			State:              c.State,
			Locality:           c.Locality,
			Organization:       c.Organization,
			OrganizationalUnit: c.OrganizationalUnit,
			CommonName:         c.Domain,
		},
		DNSNames:  []string{c.Domain},
		ValidFrom: time.Now(),
		ValidFor:  1024 * 24 * time.Hour,
		IsCA:      true,
		KeyUsage:  []string{"keyCertSign", "cRLSign"},
	}
}

func (c *CertificateConfig) GetLeafCertOptions() *CertificateOptions {
	return &CertificateOptions{
		Subject: Subject{
			Country:            c.Country,
			State:              c.State,
			Locality:           c.Locality,
			Organization:       c.Organization,
			OrganizationalUnit: c.OrganizationalUnit,
			CommonName:         c.Domain,
		},
		DNSNames:    []string{c.Domain},
		ValidFrom:   time.Now(),
		ValidFor:    time.Duration(c.ValidityDays) * 24 * time.Hour,
		IsCA:        false,
		KeyUsage:    []string{"digitalSignature", "nonRepudiation", "keyEncipherment", "dataEncipherment"},
		ExtKeyUsage: []string{"serverAuth", "clientAuth"},
	}
}
