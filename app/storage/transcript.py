"""Append-only transcript + TranscriptHash helpers."""
import hashlib
import json
from typing import List, Dict
from utils import now_ms, sha256_hex

class Transcript:
    def __init__(self, peer_name: str):
        self.peer_name = peer_name
        self.entries: List[Dict] = []
        self.filename = f"transcript_{peer_name}_{now_ms()}.txt"
    
    def add_message(self, seqno: int, timestamp: int, ciphertext: str, 
                   signature: str, peer_cert_fingerprint: str):
        """Add a message to the transcript"""
        entry = {
            'seqno': seqno,
            'timestamp': timestamp,
            'ciphertext': ciphertext,
            'signature': signature,
            'peer_cert_fingerprint': peer_cert_fingerprint
        }
        
        self.entries.append(entry)
        
        # Append to file
        with open(self.filename, 'a') as f:
            f.write(json.dumps(entry) + '\n')
    
    def compute_transcript_hash(self) -> str:
        """Compute SHA256 of all transcript entries"""
        transcript_data = ""
        for entry in self.entries:
            transcript_data += json.dumps(entry, sort_keys=True)
        
        return sha256_hex(transcript_data.encode())
    
    def get_session_receipt_data(self, first_seq: int, last_seq: int) -> Dict:
        """Generate data for session receipt"""
        return {
            "peer": self.peer_name,
            "first_seq": first_seq,
            "last_seq": last_seq,
            "transcript_sha256": self.compute_transcript_hash()
        }
    
    def verify_transcript_integrity(self, expected_hash: str) -> bool:
        """Verify that transcript hasn't been tampered with"""
        return self.compute_transcript_hash() == expected_hash
