"""Helper signatures: now_ms, b64e, b64d, sha256_hex."""
import time
import base64
import hashlib

def now_ms() -> int:
    """Get current timestamp in milliseconds"""
    return int(time.time() * 1000)

def b64e(b: bytes) -> str:
    """Base64 encode bytes to string"""
    return base64.b64encode(b).decode('utf-8')

def b64d(s: str) -> bytes:
    """Base64 decode string to bytes"""
    return base64.b64decode(s)

def sha256_hex(data: bytes) -> str:
    """Compute SHA256 hash and return as hex string"""
    return hashlib.sha256(data).hexdigest()

def generate_nonce() -> str:
    """Generate a random nonce"""
    import os
    return b64e(os.urandom(16))
