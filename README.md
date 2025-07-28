# Certificate Generator

A modular Go implementation of a certificate generator that creates Root CA and leaf certificates with PKCS#12 support. This is a Go port of the Python `fullgenerator.py` script with enhanced modularity and type safety.

## Features

- **Self-signed Root CA generation** - Creates a Certificate Authority for signing leaf certificates
- **Leaf certificate generation** - Issues certificates signed by the Root CA
- **PKCS#12 bundle support** - Packages certificates and keys for easy import
- **Multiple output formats**:
  - PEM format for certificates and keys
  - PKCS#12 (.p12) bundle with password protection
  - Base64-encoded DER format for programmatic use
- **Customizable certificate attributes** - Configure country, organization, validity period, etc.
- **Clean CLI interface** - Simple command-line usage with sensible defaults
- **Modular architecture** - Easy to extend or integrate into other applications

## Requirements

- Go 1.21 or higher
- OpenSSL command-line tool (for PKCS#12 generation)

## Quick Start

```bash
# Clone and build
git clone https://github.com/erfianugrah/certgen.git
cd certgen
make build

# Generate certificates for your domain
./certgen --domain myapp.local

# View generated files
ls -la myapp_*

# Or use make run for a quick test
make run  # Generates certificates for example.local
```

## Installation

### From source

```bash
git clone https://github.com/erfianugrah/certgen.git
cd certgen
go build -o certgen ./cmd/certgen
```

### Using go install

```bash
go install github.com/erfianugrah/certgen/cmd/certgen@latest
```

### Using go get

```bash
go get github.com/erfianugrah/certgen
```

## Usage

### Basic usage

Generate certificates for a domain with default settings:

```bash
./certgen --domain example.com
```

### Advanced usage

Customize certificate attributes:

```bash
./certgen \
  --domain myapp.local \
  --organization "My Company Inc" \
  --organizational_unit "IT Department" \
  --country US \
  --state California \
  --locality "San Francisco" \
  --days 730 \
  --p12-password "strongpassword"
```

### Command line options

| Flag | Description | Default |
|------|-------------|---------|
| `--domain` | The domain name for the certificate (required) | - |
| `--country` | Country Name (2 letter code) | SG |
| `--state` | State or Province Name | Singapore |
| `--locality` | Locality Name (city) | Singapore |
| `--organization` | Organization Name | Erfi Corp |
| `--organizational_unit` | Organizational Unit Name | Erfi Proxy |
| `--days` | Validity period for the leaf certificate (days) | 3650 |
| `--p12-password` | Password for PKCS#12 file | yourPKCS12Password |
| `--version` | Show version information | - |
| `--help` | Show help message | - |

### Output files

For a domain `example.com`, the following files will be generated:

| File | Description | Format |
|------|-------------|--------|
| `example_rootCA.key` | Root CA private key | PEM (PKCS#8) |
| `example_rootCA.pem` | Root CA certificate | PEM (X.509) |
| `example_leaf.key` | Leaf certificate private key | PEM (PKCS#8) |
| `example_leaf.pem` | Leaf certificate | PEM (X.509) |
| `example_certs.p12` | PKCS#12 bundle containing leaf cert & key | PKCS#12 |
| `example_rootCA_base64.txt` | Base64-encoded Root CA certificate | Base64 DER |
| `example_leaf_base64.txt` | Base64-encoded leaf certificate | Base64 DER |

## Certificate Details

### Root CA Certificate
- **Key Size**: 4096-bit RSA
- **Signature Algorithm**: SHA-256
- **Validity**: 1024 days (~2.8 years)
- **Key Usage**: Certificate Sign, CRL Sign
- **Basic Constraints**: CA:TRUE

### Leaf Certificate
- **Key Size**: 4096-bit RSA
- **Signature Algorithm**: SHA-256
- **Validity**: Configurable (default 3650 days/10 years)
- **Key Usage**: Digital Signature, Key Encipherment
- **Extended Key Usage**: Server Auth, Client Auth
- **Subject Alternative Names**: Includes the domain name

## Package Structure

```
certgen/
├── cmd/
│   └── certgen/         # CLI application
│       └── main.go      # Enhanced CLI with version info and better output
├── pkg/
│   ├── certificate/     # Core certificate generation logic
│   │   └── certificate.go
│   ├── config/          # Certificate configuration structures
│   │   └── config.go
│   ├── encoding/        # Format conversions (PEM/DER/Base64)
│   │   └── encoding.go
│   ├── pkcs12/          # PKCS#12 bundle generation
│   │   └── pkcs12.go
│   └── fileio/          # File I/O operations
│       └── fileio.go
├── tests/               # Comprehensive test suites
│   ├── certificate/     # Certificate generation tests
│   ├── config/         # Configuration tests
│   ├── encoding/       # Encoding/decoding tests
│   ├── fileio/         # File operations tests
│   ├── pkcs12/         # PKCS#12 generation tests
│   └── integration/    # End-to-end integration tests
├── go.mod               # Go module definition
├── Makefile             # Build and test automation
├── .gitignore           # Git ignore patterns
├── LICENSE              # MIT License
├── CHANGELOG.md         # Version history
├── README.md            # This file
└── .github/
    └── workflows/       # CI/CD configuration
        └── ci.yml       # GitHub Actions workflow
```

### Package Descriptions

- **`pkg/config`**: Defines certificate configuration structures and default values
- **`pkg/certificate`**: Implements X.509 certificate generation using Go's crypto packages
- **`pkg/encoding`**: Handles conversions between PEM, DER, and Base64 formats
- **`pkg/pkcs12`**: Creates PKCS#12 bundles using OpenSSL (Go's pkcs12 package is limited)
- **`pkg/fileio`**: Manages file operations and naming conventions
- **`cmd/certgen`**: Provides the command-line interface with argument parsing

## Development

### Building from source

```bash
# Clone the repository
git clone https://github.com/erfianugrah/certgen.git
cd certgen

# Download dependencies
make deps

# Build the binary
make build

# Install to $GOPATH/bin
make install
```

### Available Make Commands

Run `make help` to see all available commands with descriptions.

```bash
# Development
make build    # Build the binary
make run      # Build and run with example domain
make install  # Install to $GOPATH/bin
make clean    # Remove binary and test artifacts

# Testing
make test     # Run all tests
make test-race # Run tests with race detector
make test-coverage # Generate HTML coverage report
make test-coverage-report # Show coverage in terminal
make test-all # Run formatting, vetting, and tests

# Code Quality
make fmt      # Format the code
make vet      # Run go vet
make lint     # Run golangci-lint (requires installation)

# Dependencies
make deps     # Download dependencies
make tidy     # Clean up dependencies

# Release
make release  # Build binaries for multiple platforms

# Help
make help     # Show all available commands
```

### Project structure

The project follows standard Go project layout:
- `/cmd` - Main applications for this project
- `/pkg` - Library code that's ok to use by external applications
- `/tests` - Comprehensive test suites for all packages
- `/internal` - Private application and library code (not used currently)

### Testing

The project includes comprehensive test coverage (85.3%) with tests organized in the `/tests` directory:

- **Unit tests** for all packages
- **Integration tests** for end-to-end workflows
- **Edge case testing** for error conditions
- **Table-driven tests** for similar scenarios

Run tests with:
```bash
make test              # Run all tests
make test-race         # Run with race detector
make test-coverage     # Generate HTML coverage report
make test-coverage-report  # View coverage in terminal
```

### Extending the generator

The modular design makes it easy to add new features:

1. **Add new certificate types**: Extend the `certificate` package
2. **Support new output formats**: Add methods to the `encoding` package
3. **Customize file naming**: Modify the `fileio` package
4. **Add new CLI commands**: Update `cmd/certgen/main.go`

Example: Adding intermediate CA support
```go
// In pkg/certificate/certificate.go
func (g *Generator) GenerateIntermediateCA(rootCert *x509.Certificate, rootKey *rsa.PrivateKey) (*x509.Certificate, *rsa.PrivateKey, error) {
    // Implementation here
}
```

## Security Considerations

1. **Private Key Security**: Private keys are generated with 4096-bit RSA and stored unencrypted. Protect these files appropriately.

2. **PKCS#12 Passwords**: The default password is weak. Always use a strong password in production.

3. **Certificate Validation**: These are self-signed certificates. Browsers and systems will show security warnings unless the Root CA is manually trusted.

4. **Random Number Generation**: Uses Go's `crypto/rand` for secure random number generation.

## Comparison with Python Version

| Feature | Python Version | Go Version |
|---------|----------------|------------|
| Root CA generation | ✓ | ✓ |
| Leaf certificate generation | ✓ | ✓ |
| PKCS#12 support | ✓ | ✓ |
| Base64 DER output | ✓ | ✓ |
| CSR generation | ✓ | ✓ (internal) |
| Cross-platform binary | ✗ | ✓ |
| Type safety | ✗ | ✓ |
| Concurrent operations | ✗ | ✓ (possible) |
| Single file deployment | ✗ | ✓ |

## Troubleshooting

### OpenSSL not found
```
Error: failed to generate PKCS#12: exec: "openssl": executable file not found in $PATH
```
**Solution**: Install OpenSSL:
- macOS: `brew install openssl`
- Ubuntu/Debian: `sudo apt-get install openssl`
- RHEL/CentOS: `sudo yum install openssl`

### Permission denied
```
Error: failed to write file: permission denied
```
**Solution**: Ensure you have write permissions in the current directory.

### Invalid domain
```
Error: --domain flag is required
```
**Solution**: Provide a domain name using the `--domain` flag.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## TODO

- [x] Add comprehensive unit tests for all packages (85.3% coverage achieved)
- [ ] Add support for encrypted private keys
- [ ] Implement native Go PKCS#12 generation (when golang.org/x/crypto/pkcs12 supports encoding)
- [ ] Add support for EC (Elliptic Curve) keys
- [ ] Add certificate chain validation
- [ ] Add support for certificate revocation lists (CRL)
- [ ] Add JSON/YAML configuration file support
- [ ] Add support for custom certificate extensions
- [ ] Add certificate renewal functionality
- [ ] Add support for intermediate CA certificates