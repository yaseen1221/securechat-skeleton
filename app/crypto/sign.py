"""RSA PKCS#1 v1.5 SHA-256 sign/verify."""
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.exceptions import InvalidSignature

class SigningHelper:
    @staticmethod
    def load_private_key(key_path: str) -> rsa.RSAPrivateKey:
        """Load RSA private key from file"""
        with open(key_path, 'rb') as f:
            return serialization.load_pem_private_key(f.read(), password=None)
    
    @staticmethod
    def load_public_key_from_cert(cert_path: str) -> rsa.RSAPublicKey:
        """Load RSA public key from certificate"""
        from cryptography import x509
        with open(cert_path, 'rb') as f:
            cert = x509.load_pem_x509_certificate(f.read())
            return cert.public_key()
    
    @staticmethod
    def sign_data(data: bytes, private_key: rsa.RSAPrivateKey) -> bytes:
        """Sign data using RSA private key with SHA256"""
        return private_key.sign(
            data,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
    
    @staticmethod
    def verify_signature(data: bytes, signature: bytes, public_key: rsa.RSAPublicKey) -> bool:
        """Verify signature using RSA public key with SHA256"""
        try:
            public_key.verify(
                signature,
                data,
                padding.PKCS1v15(),
                hashes.SHA256()
            )
            return True
        except InvalidSignature:
            return False
