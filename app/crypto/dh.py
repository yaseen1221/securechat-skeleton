"""Classic DH helpers + Trunc16(SHA256(Ks)) derivation."""
import hashlib
import secrets

class DiffieHellman:
    # Pre-defined DH parameters (RFC 3526 - 2048-bit MODP Group)
    PRIME = int(
        "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
        "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
        "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
        "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
        "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
        "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
        "83655D23DCA3AD961C62F356208552BB9ED529077096966D"
        "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B"
        "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9"
        "DE2BCBF6955817183995497CEA956AE515D2261898FA0510"
        "15728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
    )
    GENERATOR = 2
    
    def __init__(self):
        self.private_key = secrets.randbits(256)  # 256-bit private key
        self.public_key = pow(self.GENERATOR, self.private_key, self.PRIME)
    
    def get_public_parameters(self):
        """Return public parameters (p, g, A)"""
        return {
            'p': self.PRIME,
            'g': self.GENERATOR,
            'A': self.public_key
        }
    
    def compute_shared_secret(self, other_public_key: int) -> bytes:
        """Compute shared secret Ks = other_public_key^private_key mod p"""
        shared_secret = pow(other_public_key, self.private_key, self.PRIME)
        return shared_secret.to_bytes((shared_secret.bit_length() + 7) // 8, 'big')
    
    @staticmethod
    def derive_aes_key(shared_secret: bytes) -> bytes:
        """Derive AES key: Trunc16(SHA256(Ks))"""
        hash_digest = hashlib.sha256(shared_secret).digest()
        return hash_digest[:16]  # Truncate to 16 bytes for AES-128
