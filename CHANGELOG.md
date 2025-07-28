# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.0.0] - 2024-07-28

### Added
- Initial release of the Go certificate generator
- Root CA certificate generation
- Leaf certificate generation with Root CA signing
- PKCS#12 bundle generation using OpenSSL
- Base64-encoded DER format export
- Customizable certificate attributes via CLI flags
- Comprehensive test suite with 85.3% coverage
- Modular package architecture
- Multiple output formats support
- Makefile for build automation

### Security
- Private keys are saved with restrictive permissions (0600)
- Uses crypto/rand for secure random number generation
- Validates minimum key size (1024 bits)

### Changed
- Ported from Python to Go for better performance and deployment
- Enhanced CLI with progress indicators
- Improved error handling and validation

### Known Issues
- PKCS#12 generation requires OpenSSL command-line tool
- Default PKCS#12 password should be changed for production use