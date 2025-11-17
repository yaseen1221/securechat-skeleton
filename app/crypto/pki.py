"""X.509 validation: signed-by-CA, validity window, CN/SAN."""
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.x509.oid import NameOID
from datetime import datetime
import hashlib

class PKIValidator:
    def __init__(self, ca_cert_path: str = "certs/ca.crt"):
        self.ca_cert = self._load_ca_certificate(ca_cert_path)
    
    def _load_ca_certificate(self, path: str) -> x509.Certificate:
        """Load CA certificate from file"""
        with open(path, 'rb') as f:
            return x509.load_pem_x509_certificate(f.read())
    
    def validate_certificate(self, cert_pem: bytes, expected_cn: str = None) -> dict:
        """Validate certificate against CA"""
        try:
            certificate = x509.load_pem_x509_certificate(cert_pem)
            
            # 1. Verify signature chain
            try:
                certificate.verify_directly_issued_by(self.ca_cert)
            except:
                return {"valid": False, "error": "BAD_CERT: Not signed by trusted CA"}
            
            # 2. Check validity period
            now = datetime.utcnow()
            if now < certificate.not_valid_before_utc:
                return {"valid": False, "error": "BAD_CERT: Certificate not yet valid"}
            if now > certificate.not_valid_after_utc:
                return {"valid": False, "error": "BAD_CERT: Certificate expired"}
            
            # 3. Check Common Name if provided
            if expected_cn:
                cn = certificate.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
                if not cn or cn[0].value != expected_cn:
                    return {"valid": False, "error": "BAD_CERT: CN mismatch"}
            
            # 4. Get certificate fingerprint
            fingerprint = hashlib.sha256(cert_pem).hexdigest()
            
            return {
                "valid": True,
                "fingerprint": fingerprint,
                "subject": certificate.subject,
                "issuer": certificate.issuer
            }
            
        except Exception as e:
            return {"valid": False, "error": f"BAD_CERT: {str(e)}"}
    
    def get_certificate_fingerprint(self, cert_pem: bytes) -> str:
        """Get SHA256 fingerprint of certificate"""
        return hashlib.sha256(cert_pem).hexdigest()
