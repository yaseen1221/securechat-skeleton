"""AES-128(ECB)+PKCS#7 helpers (use library)."""
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import os

class AESHelper:
    @staticmethod
    def encrypt(plaintext: bytes, key: bytes) -> bytes:
        """Encrypt plaintext using AES-128 ECB with PKCS7 padding"""
        if len(key) != 16:
            raise ValueError("AES key must be 16 bytes")
        
        # Pad the plaintext
        padder = padding.PKCS7(128).padder()
        padded_data = padder.update(plaintext) + padder.finalize()
        
        # Encrypt
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        encryptor = cipher.encryptor()
        ciphertext = encryptor.update(padded_data) + encryptor.finalize()
        
        return ciphertext
    
    @staticmethod
    def decrypt(ciphertext: bytes, key: bytes) -> bytes:
        """Decrypt ciphertext using AES-128 ECB with PKCS7 padding"""
        if len(key) != 16:
            raise ValueError("AES key must be 16 bytes")
        
        # Decrypt
        cipher = Cipher(algorithms.AES(key), modes.ECB())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Unpad
        unpadder = padding.PKCS7(128).unpadder()
        plaintext = unpadder.update(padded_plaintext) + unpadder.finalize()
        
        return plaintext
    
    @staticmethod
    def generate_key() -> bytes:
        """Generate a random 16-byte AES key"""
        return os.urandom(16)
