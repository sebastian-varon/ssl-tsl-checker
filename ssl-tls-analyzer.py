#!/usr/bin/env python3
import socket
import ssl
import datetime
import argparse
import sys
import textwrap
from colorama import init, Fore, Style
from cryptography import x509
from cryptography.hazmat.backends import default_backend

# Initialize colorama for cross-platform colored terminal output
init()

class CertificateAnalyzer:
    def __init__(self):
        self.weak_ciphers = [
            'RC4', 'DES', '3DES', 'MD5', 'NULL', 'EXPORT', 'anon'
        ]
        self.insecure_protocols = ['SSLv2', 'SSLv3', 'TLSv1.0', 'TLSv1.1']
        self.minimum_key_size = {
            'RSA': 2048,
            'DSA': 2048,
            'EC': 256,
        }
        self.warning_days = 30

    def get_certificate(self, hostname, port=443, timeout=10):
        """Connect to a server and retrieve its SSL/TLS certificate."""
        try:
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE

            with socket.create_connection((hostname, port), timeout=timeout) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                    # Get both dictionary and binary forms of the certificate
                    cert_dict = ssock.getpeercert()
                    cert_bin = ssock.getpeercert(binary_form=True)
                    cipher = ssock.cipher()
                    version = ssock.version()
                    
                    # Create x509 certificate object from binary form
                    cert_obj = x509.load_der_x509_certificate(cert_bin, default_backend())
                    
                    return cert_dict, cert_obj, cipher, version
        except ImportError:
            print(f"{Fore.RED}Error: Missing dependency 'cryptography'. Install with 'pip install cryptography'{Style.RESET_ALL}")
            sys.exit(1)
        except socket.gaierror:
            print(f"{Fore.RED}Error: Could not resolve hostname '{hostname}'{Style.RESET_ALL}")
            sys.exit(1)
        except socket.timeout:
            print(f"{Fore.RED}Error: Connection to {hostname}:{port} timed out{Style.RESET_ALL}")
            sys.exit(1)
        except ConnectionRefusedError:
            print(f"{Fore.RED}Error: Connection to {hostname}:{port} was refused{Style.RESET_ALL}")
            sys.exit(1)
        except ssl.SSLError as e:
            print(f"{Fore.RED}SSL Error: {e}{Style.RESET_ALL}")
            sys.exit(1)
        except Exception as e:
            print(f"{Fore.RED}Error: {e}{Style.RESET_ALL}")
            sys.exit(1)

    def analyze_certificate(self, hostname, port=443):
        """Analyze the SSL/TLS certificate of a server and print the results."""
        cert_dict, cert_obj, cipher, version = self.get_certificate(hostname, port)
        
        print(f"\n{Fore.CYAN}=== SSL/TLS Certificate Analysis for {hostname}:{port} ==={Style.RESET_ALL}\n")
        
        # Certificate details
        self._print_certificate_details(cert_dict, cert_obj)
        
        # Protocol and cipher details
        self._print_protocol_cipher_details(cipher, version)
        
        # Security checks
        print(f"\n{Fore.CYAN}=== Security Assessment ==={Style.RESET_ALL}")
        issues_found = self._check_security_issues(cert_dict, cert_obj, cipher, version)
        
        if not issues_found:
            print(f"{Fore.GREEN}✓ No immediate security issues found.{Style.RESET_ALL}")
            
    def _print_certificate_details(self, cert_dict, cert_obj):
        """Print details about the certificate."""
        print(f"{Fore.CYAN}Certificate Information:{Style.RESET_ALL}")
        
        # Using cryptography library to extract subject and issuer info
        subject = cert_obj.subject
        issuer = cert_obj.issuer
        
        # Get common name
        try:
            cn = [attr.value for attr in subject if attr.oid._name == 'commonName'][0]
            print(f"  • Subject: {cn}")
        except (IndexError, AttributeError):
            print(f"  • Subject: N/A")
            
        try:
            org = [attr.value for attr in subject if attr.oid._name == 'organizationName'][0]
            print(f"  • Organization: {org}")
        except (IndexError, AttributeError):
            pass
        
        try:
            issuer_cn = [attr.value for attr in issuer if attr.oid._name == 'commonName'][0]
            print(f"  • Issuer: {issuer_cn}")
        except (IndexError, AttributeError):
            print(f"  • Issuer: N/A")
            
        try:
            issuer_org = [attr.value for attr in issuer if attr.oid._name == 'organizationName'][0]
            print(f"  • Issuer Organization: {issuer_org}")
        except (IndexError, AttributeError):
            pass
        
        # Get validity period - use UTC methods to avoid deprecation warnings
        try:
            not_before = cert_obj.not_valid_before_utc
        except AttributeError:  # Fallback for older cryptography versions
            not_before = cert_obj.not_valid_before
            
        try:
            not_after = cert_obj.not_valid_after_utc
        except AttributeError:  # Fallback for older cryptography versions
            not_after = cert_obj.not_valid_after
        
        days_left = (not_after - datetime.datetime.now(datetime.timezone.utc)).days
        
        print(f"  • Valid From: {not_before.strftime('%Y-%m-%d')}")
        
        if days_left <= 0:
            print(f"  • Valid Until: {not_after.strftime('%Y-%m-%d')} {Fore.RED}(EXPIRED){Style.RESET_ALL}")
        elif days_left <= self.warning_days:
            print(f"  • Valid Until: {not_after.strftime('%Y-%m-%d')} {Fore.YELLOW}(Expires in {days_left} days){Style.RESET_ALL}")
        else:
            print(f"  • Valid Until: {not_after.strftime('%Y-%m-%d')} ({days_left} days remaining)")
        
        # Get SANs from certificate extensions
        try:
            ext = cert_obj.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            sans = ext.value.get_values_for_type(x509.DNSName)
            if sans:
                print(f"  • Subject Alternative Names (SANs):")
                for san in sans[:5]:  # Limit to 5 SANs to avoid clutter
                    print(f"    - {san}")
                if len(sans) > 5:
                    print(f"    - ... and {len(sans) - 5} more")
        except x509.extensions.ExtensionNotFound:
            pass
        
    def _print_protocol_cipher_details(self, cipher, version):
        """Print details about the protocol and cipher suite."""
        print(f"\n{Fore.CYAN}Connection Information:{Style.RESET_ALL}")
        print(f"  • Protocol: {version}")
        print(f"  • Cipher Suite: {cipher[0]}")
        print(f"  • Key Exchange: {cipher[1]}")
        print(f"  • MAC: {cipher[2]}")
        
    def _check_security_issues(self, cert_dict, cert_obj, cipher, version):
        """Check for security issues with the certificate, protocol, and cipher suite."""
        issues_found = False
        
        # Check certificate expiration
        try:
            not_after = cert_obj.not_valid_after_utc
        except AttributeError:
            not_after = cert_obj.not_valid_after
            
        days_left = (not_after - datetime.datetime.now(datetime.timezone.utc)).days
        
        if days_left <= 0:
            print(f"{Fore.RED}✗ Certificate has EXPIRED{Style.RESET_ALL}")
            issues_found = True
        elif days_left <= self.warning_days:
            print(f"{Fore.YELLOW}⚠ Certificate will expire in {days_left} days{Style.RESET_ALL}")
            issues_found = True
        
        # Check protocol version
        for insecure in self.insecure_protocols:
            if insecure in version:
                print(f"{Fore.RED}✗ Using insecure protocol: {version}{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}  Recommendation: Configure server to use TLSv1.2 or TLSv1.3 only{Style.RESET_ALL}")
                issues_found = True
                break
        
        # Check for weak ciphers
        cipher_name = cipher[0]
        for weak in self.weak_ciphers:
            if weak in cipher_name:
                print(f"{Fore.RED}✗ Using weak cipher: {cipher_name}{Style.RESET_ALL}")
                print(f"  {Fore.YELLOW}  Recommendation: Configure server to use strong cipher suites only{Style.RESET_ALL}")
                issues_found = True
                break
        
        # Check public key size
        try:
            public_key = cert_obj.public_key()
            key_size = public_key.key_size
            key_type = public_key.__class__.__name__
            
            if 'RSA' in key_type and key_size < self.minimum_key_size['RSA']:
                print(f"{Fore.RED}✗ Weak RSA key size: {key_size} bits (should be at least {self.minimum_key_size['RSA']} bits){Style.RESET_ALL}")
                issues_found = True
            elif 'DSA' in key_type and key_size < self.minimum_key_size['DSA']:
                print(f"{Fore.RED}✗ Weak DSA key size: {key_size} bits (should be at least {self.minimum_key_size['DSA']} bits){Style.RESET_ALL}")
                issues_found = True
            elif 'EC' in key_type and key_size < self.minimum_key_size['EC']:
                print(f"{Fore.RED}✗ Weak EC key size: {key_size} bits (should be at least {self.minimum_key_size['EC']} bits){Style.RESET_ALL}")
                issues_found = True
        except Exception:
            pass
        
        return issues_found

def main():
    parser = argparse.ArgumentParser(
        description='SSL/TLS Certificate Analyzer - Check HTTPS services for certificate issues',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent('''\
            Examples:
              %(prog)s example.com
              %(prog)s example.com:8443
              %(prog)s -p 8443 example.com
        ''')
    )
    parser.add_argument('host', help='The hostname to check')
    parser.add_argument('-p', '--port', type=int, default=443, 
                        help='The port to connect to (default: 443)')
    
    args = parser.parse_args()
    
    # Handle host:port format
    if ':' in args.host:
        host_parts = args.host.split(':')
        args.host = host_parts[0]
        args.port = int(host_parts[1])
    
    analyzer = CertificateAnalyzer()
    analyzer.analyze_certificate(args.host, args.port)

if __name__ == '__main__':
    main()