# Certificate Generator Tests

This directory contains comprehensive test suites for all packages in the certificate generator project.

## Test Structure

```
tests/
├── certificate/        # Tests for certificate generation logic
├── config/            # Tests for configuration structures
├── encoding/          # Tests for PEM/DER/Base64 encoding
├── fileio/           # Tests for file I/O operations
├── pkcs12/           # Tests for PKCS#12 generation
└── integration/      # End-to-end integration tests
```

## Running Tests

### Run all tests
```bash
make test
```

### Run tests with race detection
```bash
make test-race
```

### Run tests with coverage report
```bash
make test-coverage
```

### View coverage in terminal
```bash
make test-coverage-report
```

### Run specific package tests
```bash
go test -v ./tests/config/...
go test -v ./tests/certificate/...
go test -v ./tests/encoding/...
go test -v ./tests/fileio/...
go test -v ./tests/pkcs12/...
go test -v ./tests/integration/...
```

## Test Coverage

Each package has comprehensive tests covering:

### Config Package
- Default configuration values
- Root CA options generation
- Leaf certificate options generation
- Validity period calculations

### Certificate Package
- Private key generation with various key sizes
- Root CA certificate generation
- Leaf certificate generation and signing
- Certificate request (CSR) generation
- Multiple certificate generation
- Error handling for invalid inputs
- Nil configuration handling
- Special character domain support

### Encoding Package
- Certificate to PEM encoding
- Private key to PEM encoding
- PEM to DER conversion
- DER to Base64 encoding
- Round-trip encoding/decoding
- Error handling for invalid inputs

### FileIO Package
- File path generation based on domain
- File writing with directory creation
- File reading
- File existence checking
- Base64 file writing with output
- Permission handling
- Complex domain name handling

### PKCS12 Package
- PKCS#12 bundle generation
- Various password scenarios (empty, long, special chars)
- Multiple certificate handling
- Nil input handling
- OpenSSL integration testing

### Integration Tests
- Full certificate generation workflow
- Multiple domain certificate generation
- File system operations
- Error handling scenarios

## Test Requirements

- Go 1.21 or higher
- OpenSSL (for PKCS#12 tests)
- Write permissions in temp directory

## Writing New Tests

When adding new features, ensure you:

1. Create tests in the appropriate test directory
2. Follow the existing naming conventions
3. Include both positive and negative test cases
4. Test error conditions
5. Add integration tests for end-to-end scenarios

## Test Best Practices

1. **Isolation**: Each test should be independent
2. **Cleanup**: Use temp directories and clean up after tests
3. **Table-driven tests**: Use subtests for similar test cases
4. **Error messages**: Provide clear error messages
5. **Coverage**: Aim for high code coverage but focus on meaningful tests

## Continuous Integration

Tests are designed to run in CI/CD pipelines. They:
- Use temp directories to avoid conflicts
- Skip OpenSSL-dependent tests if not available
- Clean up all generated files
- Run with race detection enabled