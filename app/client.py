
"""Client skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import json
import sys
from protocol import *
from utils import *
from pki import PKIValidator
from dh import DiffieHellman
from aes import AESHelper
from sign import SigningHelper
from transcript import Transcript

class SecureChatClient:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = None
        self.session_key = None
        self.seqno = 0
        self.transcript = None
        self.server_cert_fingerprint = None
        
        # Load client certificates
        with open("certs/client.crt", "rb") as f:
            self.client_cert_pem = f.read()
        
        self.private_key = SigningHelper.load_private_key("certs/client.key")
        self.pki = PKIValidator()
    
    def connect(self):
        """Establish connection and perform handshake"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        
        # Phase 1: Certificate Exchange
        if not self._certificate_exchange():
            return False
        
        # Phase 2: Authentication
        if not self._authenticate():
            return False
        
        # Phase 3: Session Key Agreement
        if not self._establish_session_key():
            return False
        
        self.transcript = Transcript("client")
        return True
    
    def _certificate_exchange(self):
        """Perform mutual certificate authentication"""
        # Send client hello
        hello = HelloMessage(
            client_cert=self.client_cert_pem.decode('utf-8'),
            nonce=generate_nonce()
        )
        self._send_json(hello.dict())
        
        # Receive server hello
        response = self._receive_json()
        if response.get('type') != 'server_hello':
            print("Protocol error: expected server_hello")
            return False
        
        server_hello = ServerHelloMessage(**response)
        
        # Validate server certificate
        validation = self.pki.validate_certificate(
            server_hello.server_cert.encode('utf-8'),
            "localhost"  # Expected CN for server
        )
        
        if not validation['valid']:
            print(f"Server certificate validation failed: {validation['error']}")
            return False
        
        self.server_cert_fingerprint = validation['fingerprint']
        print("Server certificate validated successfully")
        return True
    
    def _authenticate(self):
        """Handle registration or login"""
        print("\n1. Register")
        print("2. Login")
        choice = input("Choose option (1 or 2): ")
        
        # Temporary DH for auth encryption
        dh_temp = DiffieHellman()
        dh_client_msg = DHClientMessage(**dh_temp.get_public_parameters())
        self._send_json(dh_client_msg.dict())
        
        # Receive server DH response
        response = self._receive_json()
        if response.get('type') != 'dh_server':
            print("Protocol error: expected dh_server")
            return False
        
        dh_server_msg = DHServerMessage(**response)
        shared_secret = dh_temp.compute_shared_secret(dh_server_msg.B)
        temp_key = DiffieHellman.derive_aes_key(shared_secret)
        
        if choice == "1":
            return self._register(temp_key)
        else:
            return self._login(temp_key)
    
    def _register(self, temp_key: bytes):
        """Handle user registration"""
        email = input("Email: ")
        username = input("Username: ")
        password = input("Password: ")
        
        # Generate salt and hash password
        import secrets
        salt = secrets.token_bytes(16)
        pwd_hash = hashlib.sha256(salt + password.encode()).digest()
        
        register_msg = RegisterMessage(
            email=email,
            username=username,
            pwd=b64e(pwd_hash),
            salt=b64e(salt)
        )
        
        # Encrypt and send registration data
        encrypted_data = AESHelper.encrypt(
            json.dumps(register_msg.dict()).encode(),
            temp_key
        )
        
        self._send_json({
            "type": "encrypted",
            "data": b64e(encrypted_data)
        })
        
        return self._handle_auth_response()
    
    def _login(self, temp_key: bytes):
        """Handle user login"""
        email = input("Email: ")
        password = input("Password: ")
        
        # For login, we need to get salt from server first
        # In a real implementation, we'd request the salt
        # For now, we'll assume the client knows the salt or it's handled differently
        
        login_msg = LoginMessage(
            email=email,
            pwd=b64e(password.encode()),  # Simplified for demo
            nonce=generate_nonce()
        )
        
        encrypted_data = AESHelper.encrypt(
            json.dumps(login_msg.dict()).encode(),
            temp_key
        )
        
        self._send_json({
            "type": "encrypted", 
            "data": b64e(encrypted_data)
        })
        
        return self._handle_auth_response()
    
    def _handle_auth_response(self):
        """Handle authentication response"""
        response = self._receive_json()
        if response.get('type') == 'auth_response':
            auth_resp = AuthResponse(**response)
            if auth_resp.status == 'success':
                print("Authentication successful!")
                return True
            else:
                print(f"Authentication failed: {auth_resp.message}")
                return False
        else:
            print("Unexpected response during authentication")
            return False
    
    def _establish_session_key(self):
        """Establish session key for chat"""
        dh_session = DiffieHellman()
        dh_client_msg = DHClientMessage(**dh_session.get_public_parameters())
        self._send_json(dh_client_msg.dict())
        
        response = self._receive_json()
        if response.get('type') != 'dh_server':
            print("Protocol error in key agreement")
            return False
        
        dh_server_msg = DHServerMessage(**response)
        shared_secret = dh_session.compute_shared_secret(dh_server_msg.B)
        self.session_key = DiffieHellman.derive_aes_key(shared_secret)
        
        print("Session key established successfully")
        return True
    
    def chat_loop(self):
        """Main chat loop"""
        print("\n=== Secure Chat Started ===")
        print("Type your messages (type '/quit' to exit)")
        
        try:
            while True:
                # Send message
                message = input("You: ")
                if message == '/quit':
                    break
                
                self._send_message(message)
                
                # Receive message
                response = self._receive_json()
                if response.get('type') == 'msg':
                    self._handle_received_message(response)
                elif response.get('type') == 'error':
                    print(f"Error: {response['error']}")
                
        except KeyboardInterrupt:
            print("\nClosing chat...")
        
        self._close_session()
    
    def _send_message(self, plaintext: str):
        """Send an encrypted and signed message"""
        self.seqno += 1
        timestamp = now_ms()
        
        # Encrypt message
        ciphertext = AESHelper.encrypt(plaintext.encode(), self.session_key)
        
        # Create message object
        msg = ChatMessage(
            seqno=self.seqno,
            ts=timestamp,
            ct=b64e(ciphertext)
        )
        
        # Sign the message
        message_digest = hashlib.sha256(
            f"{msg.seqno}{msg.ts}{msg.ct}".encode()
        ).digest()
        signature = SigningHelper.sign_data(message_digest, self.private_key)
        msg.sig = b64e(signature)
        
        # Add to transcript
        self.transcript.add_message(
            msg.seqno, msg.ts, msg.ct, msg.sig, self.server_cert_fingerprint
        )
        
        # Send message
        self._send_json(msg.dict())
    
    def _handle_received_message(self, msg_data: dict):
        """Handle received encrypted message"""
        msg = ChatMessage(**msg_data)
        
        # Verify signature
        server_pub_key = SigningHelper.load_public_key_from_cert("certs/server.crt")
        message_digest = hashlib.sha256(
            f"{msg.seqno}{msg.ts}{msg.ct}".encode()
        ).digest()
        
        if not SigningHelper.verify_signature(
            message_digest, b64d(msg.sig), server_pub_key
        ):
            print("SIG_FAIL: Message signature verification failed")
            return
        
        # Decrypt message
        try:
            plaintext = AESHelper.decrypt(b64d(msg.ct), self.session_key)
            print(f"Server: {plaintext.decode()}")
            
            # Add to transcript
            self.transcript.add_message(
                msg.seqno, msg.ts, msg.ct, msg.sig, self.server_cert_fingerprint
            )
            
        except Exception as e:
            print(f"Decryption error: {e}")
    
    def _close_session(self):
        """Generate and send session receipt"""
        if self.transcript and self.transcript.entries:
            receipt_data = self.transcript.get_session_receipt_data(
                1, len(self.transcript.entries)
            )
            
            # Sign the transcript hash
            transcript_hash = receipt_data['transcript_sha256'].encode()
            signature = SigningHelper.sign_data(transcript_hash, self.private_key)
            
            receipt = ReceiptMessage(
                **receipt_data,
                sig=b64e(signature)
            )
            
            self._send_json(receipt.dict())
            print("Session receipt sent")
        
        self.socket.close()
        print("Connection closed")
    
    def _send_json(self, data: dict):
        """Send JSON data over socket"""
        message = json.dumps(data).encode('utf-8')
        self.socket.send(len(message).to_bytes(4, 'big'))
        self.socket.send(message)
    
    def _receive_json(self) -> dict:
        """Receive JSON data from socket"""
        length_bytes = self.socket.recv(4)
        if not length_bytes:
            return {}
        
        length = int.from_bytes(length_bytes, 'big')
        data = b''
        while len(data) < length:
            chunk = self.socket.recv(length - len(data))
            if not chunk:
                break
            data += chunk
        
        return json.loads(data.decode('utf-8'))

def main():
    client = SecureChatClient()
    
    if client.connect():
        client.chat_loop()
    else:
        print("Failed to establish secure connection")

if __name__ == "__main__":
    main()
