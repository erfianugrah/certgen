package main

import (
	"flag"
	"fmt"
	"log"
	"os"

	"github.com/erfianugrah/certgen/pkg/certificate"
	"github.com/erfianugrah/certgen/pkg/config"
	"github.com/erfianugrah/certgen/pkg/encoding"
	"github.com/erfianugrah/certgen/pkg/fileio"
	"github.com/erfianugrah/certgen/pkg/pkcs12"
)

var (
	version = "1.0.0"
)

func main() {
	var (
		showVersion bool
		cfg         = config.NewCertificateConfig()
	)

	flag.StringVar(&cfg.Domain, "domain", "", "The domain name for the leaf certificate (required)")
	flag.StringVar(&cfg.Country, "country", cfg.Country, "Country Name")
	flag.StringVar(&cfg.State, "state", cfg.State, "State or Province Name")
	flag.StringVar(&cfg.Locality, "locality", cfg.Locality, "Locality Name")
	flag.StringVar(&cfg.Organization, "organization", cfg.Organization, "Organization Name")
	flag.StringVar(&cfg.OrganizationalUnit, "organizational_unit", cfg.OrganizationalUnit, "Organizational Unit Name")
	flag.IntVar(&cfg.ValidityDays, "days", cfg.ValidityDays, "Validity period for the leaf certificate")
	flag.StringVar(&cfg.PKCS12Password, "p12-password", cfg.PKCS12Password, "Password for PKCS#12 file")
	flag.BoolVar(&showVersion, "version", false, "Show version information")
	
	flag.Usage = func() {
		fmt.Fprintf(os.Stderr, "Certificate Generator v%s\n\n", version)
		fmt.Fprintf(os.Stderr, "Usage: %s [options]\n\n", os.Args[0])
		fmt.Fprintf(os.Stderr, "Options:\n")
		flag.PrintDefaults()
		fmt.Fprintf(os.Stderr, "\nExample:\n")
		fmt.Fprintf(os.Stderr, "  %s --domain example.com --organization \"My Company\" --days 365\n", os.Args[0])
	}
	
	flag.Parse()

	if showVersion {
		fmt.Printf("Certificate Generator v%s\n", version)
		os.Exit(0)
	}

	if cfg.Domain == "" {
		fmt.Fprintln(os.Stderr, "Error: --domain flag is required")
		flag.Usage()
		os.Exit(1)
	}

	if cfg.ValidityDays <= 0 || cfg.ValidityDays > 36500 {
		fmt.Fprintln(os.Stderr, "Error: --days must be between 1 and 36500 (100 years)")
		os.Exit(1)
	}

	if err := run(cfg); err != nil {
		log.Fatalf("Error: %v", err)
	}
}

func run(cfg *config.CertificateConfig) error {
	certGen := certificate.NewGenerator(cfg)
	fileWriter := fileio.NewFileWriter(cfg.Domain)
	pkcs12Gen := pkcs12.NewGenerator()

	fmt.Printf("Generating certificates for domain: %s\n", cfg.Domain)
	fmt.Printf("Organization: %s\n", cfg.Organization)
	fmt.Printf("Validity: %d days\n\n", cfg.ValidityDays)

	rootCert, rootKey, err := certGen.GenerateRootCA()
	if err != nil {
		return fmt.Errorf("failed to generate root CA: %w", err)
	}
	fmt.Println("✓ Generated Root CA certificate")

	rootKeyPEM, err := encoding.EncodePrivateKeyToPEM(rootKey)
	if err != nil {
		return fmt.Errorf("failed to encode root key: %w", err)
	}
	if err := fileWriter.WriteFile(fileWriter.GetRootKeyPath(), rootKeyPEM); err != nil {
		return err
	}
	fmt.Printf("✓ Saved Root CA key: %s\n", fileWriter.GetRootKeyPath())

	rootCertPEM, err := encoding.EncodeCertificateToPEM(rootCert)
	if err != nil {
		return fmt.Errorf("failed to encode root certificate: %w", err)
	}
	if err := fileWriter.WriteFile(fileWriter.GetRootCertPath(), rootCertPEM); err != nil {
		return err
	}
	fmt.Printf("✓ Saved Root CA certificate: %s\n", fileWriter.GetRootCertPath())

	leafCert, leafKey, err := certGen.GenerateLeafCertificate(rootCert, rootKey)
	if err != nil {
		return fmt.Errorf("failed to generate leaf certificate: %w", err)
	}
	fmt.Println("✓ Generated leaf certificate")

	leafKeyPEM, err := encoding.EncodePrivateKeyToPEM(leafKey)
	if err != nil {
		return fmt.Errorf("failed to encode leaf key: %w", err)
	}
	if err := fileWriter.WriteFile(fileWriter.GetLeafKeyPath(), leafKeyPEM); err != nil {
		return err
	}
	fmt.Printf("✓ Saved leaf key: %s\n", fileWriter.GetLeafKeyPath())

	leafCertPEM, err := encoding.EncodeCertificateToPEM(leafCert)
	if err != nil {
		return fmt.Errorf("failed to encode leaf certificate: %w", err)
	}
	if err := fileWriter.WriteFile(fileWriter.GetLeafCertPath(), leafCertPEM); err != nil {
		return err
	}
	fmt.Printf("✓ Saved leaf certificate: %s\n", fileWriter.GetLeafCertPath())

	pfxData, err := pkcs12Gen.GeneratePKCS12(leafCert, leafKey, rootCert, cfg.PKCS12Password)
	if err != nil {
		return fmt.Errorf("failed to generate PKCS#12: %w", err)
	}
	if err := fileWriter.WriteFile(fileWriter.GetPKCS12Path(), pfxData); err != nil {
		return err
	}
	fmt.Printf("✓ Generated PKCS#12 file: %s\n", fileWriter.GetPKCS12Path())

	leafBase64, err := encoding.ConvertCertificateToBase64DER(leafCert)
	if err != nil {
		return fmt.Errorf("failed to convert leaf certificate to base64: %w", err)
	}
	if err := fileWriter.WriteBase64File(fileWriter.GetLeafBase64Path(), leafBase64); err != nil {
		return err
	}

	rootBase64, err := encoding.ConvertCertificateToBase64DER(rootCert)
	if err != nil {
		return fmt.Errorf("failed to convert root certificate to base64: %w", err)
	}
	if err := fileWriter.WriteBase64File(fileWriter.GetRootBase64Path(), rootBase64); err != nil {
		return err
	}

	fmt.Println("\n✓ Certificate generation completed successfully!")
	fmt.Printf("\nGenerated files:\n")
	fmt.Printf("  - Root CA key:        %s\n", fileWriter.GetRootKeyPath())
	fmt.Printf("  - Root CA cert:       %s\n", fileWriter.GetRootCertPath())
	fmt.Printf("  - Leaf key:           %s\n", fileWriter.GetLeafKeyPath())
	fmt.Printf("  - Leaf cert:          %s\n", fileWriter.GetLeafCertPath())
	fmt.Printf("  - PKCS#12 bundle:     %s\n", fileWriter.GetPKCS12Path())
	fmt.Printf("  - Root CA (base64):   %s\n", fileWriter.GetRootBase64Path())
	fmt.Printf("  - Leaf cert (base64): %s\n", fileWriter.GetLeafBase64Path())

	return nil
}