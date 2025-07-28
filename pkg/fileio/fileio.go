// Package fileio handles file operations for certificates and keys,
// including path generation and file writing with appropriate permissions.
package fileio

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type FileWriter struct {
	subdomain string
}

func NewFileWriter(domain string) *FileWriter {
	subdomain := strings.Split(domain, ".")[0]
	return &FileWriter{
		subdomain: subdomain,
	}
}

func (fw *FileWriter) GetRootKeyPath() string {
	return fmt.Sprintf("%s_rootCA.key", fw.subdomain)
}

func (fw *FileWriter) GetRootCertPath() string {
	return fmt.Sprintf("%s_rootCA.pem", fw.subdomain)
}

func (fw *FileWriter) GetLeafKeyPath() string {
	return fmt.Sprintf("%s_leaf.key", fw.subdomain)
}

func (fw *FileWriter) GetLeafCertPath() string {
	return fmt.Sprintf("%s_leaf.pem", fw.subdomain)
}

func (fw *FileWriter) GetLeafCSRPath() string {
	return fmt.Sprintf("%s_leaf.csr", fw.subdomain)
}

func (fw *FileWriter) GetPKCS12Path() string {
	return fmt.Sprintf("%s_certs.p12", fw.subdomain)
}

func (fw *FileWriter) GetRootBase64Path() string {
	return fmt.Sprintf("%s_rootCA_base64.txt", fw.subdomain)
}

func (fw *FileWriter) GetLeafBase64Path() string {
	return fmt.Sprintf("%s_leaf_base64.txt", fw.subdomain)
}

func (fw *FileWriter) WriteFile(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0755); err != nil {
		return fmt.Errorf("failed to create directory: %w", err)
	}

	// Use restrictive permissions for key files
	perm := os.FileMode(0644)
	if strings.Contains(path, ".key") {
		perm = 0600
	}

	if err := os.WriteFile(path, data, perm); err != nil {
		return fmt.Errorf("failed to write file %s: %w", path, err)
	}

	return nil
}

func (fw *FileWriter) WriteBase64File(path string, base64Data string) error {
	if err := fw.WriteFile(path, []byte(base64Data)); err != nil {
		return err
	}
	fmt.Printf("Base64-encoded DER content written to %s:\n%s\n\n", path, base64Data)
	return nil
}

func (fw *FileWriter) ReadFile(path string) ([]byte, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file %s: %w", path, err)
	}
	return data, nil
}

func (fw *FileWriter) FileExists(path string) bool {
	_, err := os.Stat(path)
	return err == nil
}
