package fileio_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/erfianugrah/certgen/pkg/fileio"
)

func TestNewFileWriter(t *testing.T) {
	tests := []struct {
		domain    string
		subdomain string
	}{
		{"example.com", "example"},
		{"sub.example.com", "sub"},
		{"deep.sub.example.com", "deep"},
		{"localhost", "localhost"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			fw := fileio.NewFileWriter(tt.domain)
			if fw == nil {
				t.Fatal("NewFileWriter returned nil")
			}
			// We can't directly test the subdomain field as it's private,
			// but we can test its effect through the public methods
		})
	}
}

func TestFileWriter_Paths(t *testing.T) {
	fw := fileio.NewFileWriter("test.example.com")

	tests := []struct {
		name     string
		method   func() string
		expected string
	}{
		{"GetRootKeyPath", fw.GetRootKeyPath, "test_rootCA.key"},
		{"GetRootCertPath", fw.GetRootCertPath, "test_rootCA.pem"},
		{"GetLeafKeyPath", fw.GetLeafKeyPath, "test_leaf.key"},
		{"GetLeafCertPath", fw.GetLeafCertPath, "test_leaf.pem"},
		{"GetLeafCSRPath", fw.GetLeafCSRPath, "test_leaf.csr"},
		{"GetPKCS12Path", fw.GetPKCS12Path, "test_certs.p12"},
		{"GetRootBase64Path", fw.GetRootBase64Path, "test_rootCA_base64.txt"},
		{"GetLeafBase64Path", fw.GetLeafBase64Path, "test_leaf_base64.txt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.method()
			if got != tt.expected {
				t.Errorf("%s() = %s, want %s", tt.name, got, tt.expected)
			}
		})
	}
}

func TestFileWriter_WriteFile(t *testing.T) {
	// Create temp directory for testing
	tempDir, err := os.MkdirTemp("", "fileio_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	fw := fileio.NewFileWriter("test.com")
	testData := []byte("test file content")
	testPath := filepath.Join(tempDir, "test.txt")

	// Test writing file
	err = fw.WriteFile(testPath, testData)
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Verify file exists
	if !fw.FileExists(testPath) {
		t.Error("File should exist after writing")
	}

	// Verify content
	readData, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	if string(readData) != string(testData) {
		t.Errorf("File content = %s, want %s", string(readData), string(testData))
	}
}

func TestFileWriter_WriteFile_CreateDirectory(t *testing.T) {
	// Create temp directory for testing
	tempDir, err := os.MkdirTemp("", "fileio_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	fw := fileio.NewFileWriter("test.com")
	testData := []byte("test content")
	testPath := filepath.Join(tempDir, "subdir", "nested", "test.txt")

	// Test writing file in non-existent directory
	err = fw.WriteFile(testPath, testData)
	if err != nil {
		t.Fatalf("WriteFile should create directories: %v", err)
	}

	// Verify file exists
	if !fw.FileExists(testPath) {
		t.Error("File should exist after writing")
	}
}

func TestFileWriter_WriteBase64File(t *testing.T) {
	// Create temp directory for testing
	tempDir, err := os.MkdirTemp("", "fileio_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	fw := fileio.NewFileWriter("test.com")
	base64Data := "VGVzdCBiYXNlNjQgZGF0YQ=="
	testPath := filepath.Join(tempDir, "test_base64.txt")

	// Capture stdout to verify print output
	err = fw.WriteBase64File(testPath, base64Data)
	if err != nil {
		t.Fatalf("WriteBase64File failed: %v", err)
	}

	// Verify file exists
	if !fw.FileExists(testPath) {
		t.Error("File should exist after writing")
	}

	// Verify content
	readData, err := os.ReadFile(testPath)
	if err != nil {
		t.Fatalf("Failed to read file: %v", err)
	}

	if string(readData) != base64Data {
		t.Errorf("File content = %s, want %s", string(readData), base64Data)
	}
}

func TestFileWriter_ReadFile(t *testing.T) {
	// Create temp directory for testing
	tempDir, err := os.MkdirTemp("", "fileio_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	fw := fileio.NewFileWriter("test.com")
	testData := []byte("test read content")
	testPath := filepath.Join(tempDir, "test_read.txt")

	// Write test file
	err = os.WriteFile(testPath, testData, 0644)
	if err != nil {
		t.Fatalf("Failed to write test file: %v", err)
	}

	// Test reading file
	readData, err := fw.ReadFile(testPath)
	if err != nil {
		t.Fatalf("ReadFile failed: %v", err)
	}

	if string(readData) != string(testData) {
		t.Errorf("ReadFile content = %s, want %s", string(readData), string(testData))
	}
}

func TestFileWriter_ReadFile_NotExist(t *testing.T) {
	fw := fileio.NewFileWriter("test.com")

	_, err := fw.ReadFile("/non/existent/file.txt")
	if err == nil {
		t.Error("ReadFile should return error for non-existent file")
	}
}

func TestFileWriter_FileExists(t *testing.T) {
	// Create temp directory for testing
	tempDir, err := os.MkdirTemp("", "fileio_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	fw := fileio.NewFileWriter("test.com")
	existingFile := filepath.Join(tempDir, "exists.txt")
	nonExistentFile := filepath.Join(tempDir, "not_exists.txt")

	// Create test file
	err = os.WriteFile(existingFile, []byte("test"), 0644)
	if err != nil {
		t.Fatalf("Failed to create test file: %v", err)
	}

	tests := []struct {
		name     string
		path     string
		expected bool
	}{
		{"Existing file", existingFile, true},
		{"Non-existent file", nonExistentFile, false},
		{"Directory", tempDir, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exists := fw.FileExists(tt.path)
			if exists != tt.expected {
				t.Errorf("FileExists(%s) = %v, want %v", tt.path, exists, tt.expected)
			}
		})
	}
}

func TestFileWriter_ComplexDomain(t *testing.T) {
	tests := []struct {
		domain         string
		expectedPrefix string
	}{
		{"simple.com", "simple"},
		{"sub.domain.com", "sub"},
		{"deep.sub.domain.com", "deep"},
		{"localhost", "localhost"},
		{"127.0.0.1", "127"},
		{"my-app.local", "my-app"},
		{"test_underscore.com", "test_underscore"},
	}

	for _, tt := range tests {
		t.Run(tt.domain, func(t *testing.T) {
			fw := fileio.NewFileWriter(tt.domain)

			// Test that paths use the correct prefix
			rootKeyPath := fw.GetRootKeyPath()
			expectedPath := tt.expectedPrefix + "_rootCA.key"
			if rootKeyPath != expectedPath {
				t.Errorf("GetRootKeyPath() = %s, want %s", rootKeyPath, expectedPath)
			}
		})
	}
}

func TestFileWriter_WriteFile_Permissions(t *testing.T) {
	// Create temp directory for testing
	tempDir, err := os.MkdirTemp("", "fileio_test")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tempDir)

	fw := fileio.NewFileWriter("test.com")
	testPath := filepath.Join(tempDir, "test_perms.txt")

	err = fw.WriteFile(testPath, []byte("test"))
	if err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Check file permissions
	info, err := os.Stat(testPath)
	if err != nil {
		t.Fatalf("Failed to stat file: %v", err)
	}

	// Should be readable and writable by owner
	perm := info.Mode().Perm()
	if perm != 0644 {
		t.Errorf("File permissions = %o, want %o", perm, 0644)
	}
}
