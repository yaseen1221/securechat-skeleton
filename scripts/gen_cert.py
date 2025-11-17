"""Issue server/client cert signed by Root CA (SAN=DNSName(CN))."""
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import sys
import os

def load_ca():
    """Load CA private key and certificate"""
    with open("certs/ca.key", "rb") as f:
        ca_key = serialization.load_pem_private_key(f.read(), password=None)
    
    with open("certs/ca.crt", "rb") as f:
        ca_cert = x509.load_pem_x509_certificate(f.read())
    
    return ca_key, ca_cert

def generate_certificate(common_name, cert_type="server"):
    """Generate a certificate signed by the CA"""
    ca_key, ca_cert = load_ca()
    
    # Generate private key for the certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Build subject name
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat"),
        x509.NameAttribute(NameOID.COMMON_NAME, common_name),
    ])
    
    builder = x509.CertificateBuilder()
    builder = builder.subject_name(subject)
    builder = builder.issuer_name(ca_cert.subject)
    builder = builder.public_key(private_key.public_key())
    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.not_valid_before(datetime.utcnow())
    builder = builder.not_valid_after(datetime.utcnow() + timedelta(days=365))
    
    # Add appropriate extensions
    if cert_type == "server":
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(common_name)]),
            critical=False
        )
    
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None),
        critical=True
    )
    
    # Sign the certificate
    certificate = builder.sign(ca_key, hashes.SHA256())
    
    # Save files
    prefix = "certs/server" if cert_type == "server" else "certs/client"
    
    # Save private key
    with open(f"{prefix}.key", "wb") as f:
        f.write(private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save certificate
    with open(f"{prefix}.crt", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))
    
    print(f"{cert_type.capitalize()} certificate generated for {common_name}")
    print(f"Files created: {prefix}.key, {prefix}.crt")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python gen_cert.py <common_name> <server|client>")
        sys.exit(1)
    
    common_name = sys.argv[1]
    cert_type = sys.argv[2]
    
    if cert_type not in ["server", "client"]:
        print("Certificate type must be 'server' or 'client'")
        sys.exit(1)
    
    generate_certificate(common_name, cert_type)
