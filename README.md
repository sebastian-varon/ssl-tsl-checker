# SSL/TLS Certificate Analyzer

A powerful command-line tool for analyzing SSL/TLS certificates and identifying security vulnerabilities in HTTPS implementations.

## Overview

SSL/TLS Certificate Analyzer is a security tool that connects to HTTPS services, retrieves certificate details, and performs comprehensive checks for issues such as:

- Certificate expiration
- Weak cipher suites
- Outdated TLS protocols
- Insufficient key sizes
- Subject Alternative Name (SAN) validation

This tool helps security professionals, system administrators, and developers quickly assess the security posture of web services and identify potential vulnerabilities before they can be exploited.

## Features

- **Certificate Information**: Displays subject, issuer, validity dates, and SANs
- **Protocol Analysis**: Identifies SSL/TLS version and cipher suite details
- **Security Assessment**: Evaluates encryption strength with clear recommendations
- **Expiration Tracking**: Shows remaining validity period with visual warnings
- **Key Size Checking**: Verifies public key meets modern security standards
- **Colored Output**: Intuitive color-coded results for quick analysis

## Installation

```bash
# Clone the repository
git clone https://github.com/sebastian-varon/ssl-tls-analyzer.git
cd ssl-tls-analyzer

# Install dependencies
pip install -r requirements.txt
```

### Requirements

- Python 3.7 or higher
- colorama
- cryptography

## Usage

Basic usage:

```bash
python ssl-tls-analyzer.py example.com
```

Specify a custom port:

```bash
python ssl-tls-analyzer.py example.com:8443
```

Or use the port option:

```bash
python ssl-tls-analyzer.py -p 8443 example.com
```

## Example Output

```
=== SSL/TLS Certificate Analysis for example.com:443 ===

Certificate Information:
  • Subject: example.com
  • Organization: Example Organization, Inc.
  • Issuer: DigiCert TLS RSA SHA256 2020 CA1
  • Issuer Organization: DigiCert Inc
  • Valid From: 2023-05-15
  • Valid Until: 2024-05-14 (298 days remaining)
  • Subject Alternative Names (SANs):
    - example.com
    - www.example.com
    - api.example.com

Connection Information:
  • Protocol: TLSv1.3
  • Cipher Suite: TLS_AES_256_GCM_SHA384
  • Key Exchange: X25519
  • MAC: AEAD

=== Security Assessment ===
✓ No immediate security issues found.
```

## Security Checks

The analyzer performs the following security checks:

1. **Certificate Expiration**:
   - Warns when certificates are expiring within 30 days
   - Marks expired certificates as critical issues

2. **Protocol Version**:
   - Flags insecure protocols (SSLv2, SSLv3, TLSv1.0, TLSv1.1)
   - Recommends upgrading to TLSv1.2 or TLSv1.3

3. **Cipher Strength**:
   - Identifies weak algorithms (RC4, DES, 3DES, MD5, etc.)
   - Suggests strong cipher suite alternatives

4. **Key Size**:
   - Verifies RSA keys are at least 2048 bits
   - Ensures EC keys are at least 256 bits
   - Checks DSA keys meet minimum security requirements

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Future Enhancements

- Certificate chain validation
- Certificate Transparency (CT) logs verification
- OCSP stapling support
- Output in multiple formats (JSON, CSV)
- Bulk scanning for multiple hosts
- Integration with vulnerability databases

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Acknowledgments

- Inspired by the need for quick SSL/TLS security assessments
- Built with Python's ssl and cryptography libraries
