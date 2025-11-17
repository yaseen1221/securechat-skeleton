"""Create Root CA (RSA + self-signed X.509) using cryptography."""
from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from datetime import datetime, timedelta
import os

def generate_ca():
    # Create certs directory if it doesn't exist
    os.makedirs("certs", exist_ok=True)
    
    # Generate CA private key
    ca_private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    
    # Generate CA certificate
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SecureChat CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "SecureChat Root CA"),
    ])
    
    ca_cert = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        ca_private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.utcnow()
    ).not_valid_after(
        datetime.utcnow() + timedelta(days=3650)  # 10 years
    ).add_extension(
        x509.BasicConstraints(ca=True, path_length=None), critical=True,
    ).sign(ca_private_key, hashes.SHA256())
    
    # Save CA private key
    with open("certs/ca.key", "wb") as f:
        f.write(ca_private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        ))
    
    # Save CA certificate
    with open("certs/ca.crt", "wb") as f:
        f.write(ca_cert.public_bytes(serialization.Encoding.PEM))
    
    print("Root CA generated successfully!")
    print("Files created: certs/ca.key, certs/ca.crt")

if __name__ == "__main__":
    generate_ca()
