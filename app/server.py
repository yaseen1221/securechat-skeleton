"""Server skeleton — plain TCP; no TLS. See assignment spec."""
import socket
import threading
import json
import sys
from protocol import *
from utils import *
from pki import PKIValidator
from dh import DiffieHellman
from aes import AESHelper
from sign import SigningHelper
from transcript import Transcript
from db import db

class SecureChatServer:
    def __init__(self, host='localhost', port=8888):
        self.host = host
        self.port = port
        self.socket = None
        self.clients = {}
        
        # Initialize database
        db.initialize()
        
        # Load server certificates
        with open("certs/server.crt", "rb") as f:
            self.server_cert_pem = f.read()
        
        self.private_key = SigningHelper.load_private_key("certs/server.key")
        self.pki = PKIValidator()
    
    def start(self):
        """Start the server"""
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        
        print(f"Secure Chat Server listening on {self.host}:{self.port}")
        
        try:
            while True:
                client_socket, address = self.socket.accept()
                print(f"New connection from {address}")
                
                client_handler = ClientHandler(client_socket, address, self)
                client_handler.start()
                
        except KeyboardInterrupt:
            print("\nShutting down server...")
        finally:
            self.socket.close()
            db.close()

class ClientHandler(threading.Thread):
    def __init__(self, socket, address, server):
        super().__init__()
        self.socket = socket
        self.address = address
        self.server = server
        self.client_info = {}
        self.session_key = None
        self.seqno = 0
        self.expected_seqno = 1
        self.transcript = None
    
    def run(self):
        """Handle client connection"""
        try:
            # Phase 1: Certificate Exchange
            if not self._certificate_exchange():
                return
            
            # Phase 2: Authentication
            if not self._authenticate():
                return
            
            # Phase 3: Session Key Agreement
            if not self._establish_session_key():
                return
            
            self.transcript = Transcript("server")
            self._chat_loop()
            
        except Exception as e:
            print(f"Error handling client {self.address}: {e}")
        finally:
            self.socket.close()
            print(f"Connection closed for {self.address}")
    
    def _certificate_exchange(self):
        """Perform mutual certificate authentication"""
        # Receive client hello
        data = self._receive_json()
        if not data or data.get('type') != 'hello':
            self._send_error("Protocol error: expected hello")
            return False
        
        hello = HelloMessage(**data)
        
        # Validate client certificate
        validation = self.server.pki.validate_certificate(
            hello.client_cert.encode('utf-8')
        )
        
        if not validation['valid']:
            self._send_error(validation['error'])
            return False
        
        self.client_info['cert_fingerprint'] = validation['fingerprint']
        
        # Send server hello
        server_hello = ServerHelloMessage(
            server_cert=self.server.server_cert_pem.decode('utf-8'),
            nonce=generate_nonce()
        )
        self._send_json(server_hello.dict())
        
        print(f"Client certificate validated: {validation['subject']}")
        return True
    
    def _authenticate(self):
        """Handle client authentication"""
        # Receive temporary DH parameters
        data = self._receive_json()
        if not data or data.get('type') != 'dh_client':
            self._send_error("Protocol error: expected dh_client")
            return False
        
        dh_temp = DiffieHellman()
        dh_client_msg = DHClientMessage(**data)
        
        # Compute shared secret and derive temp key
        shared_secret = dh_temp.compute_shared_secret(dh_client_msg.A)
        temp_key = DiffieHellman.derive_aes_key(shared_secret)
        
        # Send server DH response
        dh_server_msg = DHServerMessage(B=dh_temp.public_key)
        self._send_json(dh_server_msg.dict())
        
        # Receive encrypted auth data
        data = self._receive_json()
        if not data or data.get('type') != 'encrypted':
            self._send_error("Protocol error: expected encrypted auth data")
            return False
        
        # Decrypt auth data
        try:
            encrypted_data = b64d(data['data'])
            decrypted_data = AESHelper.decrypt(encrypted_data, temp_key)
            auth_data = json.loads(decrypted_data)
            
            if auth_data['type'] == 'register':
                return self._handle_registration(auth_data)
            elif auth_data['type'] == 'login':
                return self._handle_login(auth_data)
            else:
                self._send_error("Unknown auth type")
                return False
                
        except Exception as e:
            self._send_error(f"Authentication error: {str(e)}")
            return False
    
    def _handle_registration(self, register_data: dict):
        """Handle user registration"""
        register_msg = RegisterMessage(**register_data)
        
        # Check if user already exists
        if db.verify_user(register_msg.email, ""):  # Just checking existence
            self._send_auth_response(False, "User already exists")
            return False
        
        # Create user (password is already hashed in the message)
        success = db.create_user(
            register_msg.email,
            register_msg.username,
            b64d(register_msg.pwd).hex()  # Store the pre-hashed password
        )
        
        if success:
            self._send_auth_response(True, "Registration successful")
            self.client_info['username'] = register_msg.username
            return True
        else:
            self._send_auth_response(False, "Registration failed")
            return False
    
    def _handle_login(self, login_data: dict):
        """Handle user login"""
        login_msg = LoginMessage(**login_data)
        
        # Verify user credentials
        user_info = db.verify_user(login_msg.email, b64d(login_msg.pwd).decode())
        
        if user_info:
            self._send_auth_response(True, "Login successful")
            self.client_info['username'] = user_info['username']
            return True
        else:
            self._send_auth_response(False, "Invalid credentials")
            return False
    
    def _establish_session_key(self):
        """Establish session key for chat"""
        # Receive client DH parameters
        data = self._receive_json()
        if not data or data.get('type') != 'dh_client':
            self._send_error("Protocol error: expected dh_client")
            return False
        
        dh_session = DiffieHellman()
        dh_client_msg = DHClientMessage(**data)
        
        # Compute shared secret and derive session key
        shared_secret = dh_session.compute_shared_secret(dh_client_msg.A)
        self.session_key = DiffieHellman.derive_aes_key(shared_secret)
        
        # Send server DH response
        dh_server_msg = DHServerMessage(B=dh_session.public_key)
        self._send_json(dh_server_msg.dict())
        
        print(f"Session key established for {self.client_info.get('username', 'unknown')}")
        return True
    
    def _chat_loop(self):
        """Main chat loop"""
        print(f"Chat session started with {self.client_info.get('username', 'unknown')}")
        
        try:
            while True:
                data = self._receive_json()
                if not data:
                    break
                
                if data.get('type') == 'msg':
                    if not self._handle_received_message(data):
                        break
                elif data.get('type') == 'receipt':
                    self._handle_session_receipt(data)
                    break
                elif data.get('type') == 'error':
                    print(f"Client error: {data['error']}")
                    break
                    
        except Exception as e:
            print(f"Chat error: {e}")
        
        self._close_session()
    
    def _handle_received_message(self, msg_data: dict) -> bool:
        """Handle received message and send response"""
        msg = ChatMessage(**msg_data)
        
        # Replay protection
        if msg.seqno != self.expected_seqno:
            self._send_error("REPLAY: Sequence number mismatch")
            return False
        
        self.expected_seqno += 1
        
        # Verify signature
        client_pub_key = SigningHelper.load_public_key_from_cert("certs/client.crt")
        message_digest = hashlib.sha256(
            f"{msg.seqno}{msg.ts}{msg.ct}".encode()
        ).digest()
        
        if not SigningHelper.verify_signature(
            message_digest, b64d(msg.sig), client_pub_key
        ):
            self._send_error("SIG_FAIL: Signature verification failed")
            return False
        
        # Decrypt message
        try:
            plaintext = AESHelper.decrypt(b64d(msg.ct), self.session_key)
            print(f"Client {self.client_info.get('username')}: {plaintext.decode()}")
            
            # Add to transcript
            self.transcript.add_message(
                msg.seqno, msg.ts, msg.ct, msg.sig, self.client_info['cert_fingerprint']
            )
            
            # Send response
            self._send_message(f"Echo: {plaintext.decode()}")
            
        except Exception as e:
            self._send_error(f"Decryption error: {e}")
            return False
        
        return True
    
    def _send_message(self, plaintext: str):
        """Send encrypted and signed message to client"""
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
        signature = SigningHelper.sign_data(message_digest, self.server.private_key)
        msg.sig = b64e(signature)
        
        # Add to transcript
        if self.transcript:
            self.transcript.add_message(
                msg.seqno, msg.ts, msg.ct, msg.sig, self.client_info['cert_fingerprint']
            )
        
        # Send message
        self._send_json(msg.dict())
    
    def _handle_session_receipt(self, receipt_data: dict):
        """Handle session receipt from client"""
        receipt = ReceiptMessage(**receipt_data)
        print(f"Received session receipt from client: {receipt.transcript_sha256}")
        
        # Verify receipt signature
        client_pub_key = SigningHelper.load_public_key_from_cert("certs/client.crt")
        transcript_hash = receipt.transcript_sha256.encode()
        
        if SigningHelper.verify_signature(
            transcript_hash, b64d(receipt.sig), client_pub_key
        ):
            print("Client session receipt verified successfully")
        else:
            print("Client session receipt verification failed")
    
    def _close_session(self):
        """Generate and send session receipt"""
        if self.transcript and self.transcript.entries:
            receipt_data = self.transcript.get_session_receipt_data(
                1, len(self.transcript.entries)
            )
            
            # Sign the transcript hash
            transcript_hash = receipt_data['transcript_sha256'].encode()
            signature = SigningHelper.sign_data(transcript_hash, self.server.private_key)
            
            receipt = ReceiptMessage(
                **receipt_data,
                sig=b64e(signature)
            )
            
            self._send_json(receipt.dict())
            print("Session receipt sent to client")
    
    def _send_auth_response(self, success: bool, message: str = ""):
        """Send authentication response"""
        response = AuthResponse(
            status="success" if success else "failure",
            message=message
        )
        self._send_json(response.dict())
    
    def _send_error(self, error: str):
        """Send error message"""
        error_msg = ErrorMessage(error=error)
        self._send_json(error_msg.dict())
    
    def _send_json(self, data: dict):
        """Send JSON data over socket"""
        try:
            message = json.dumps(data).encode('utf-8')
            self.socket.send(len(message).to_bytes(4, 'big'))
            self.socket.send(message)
        except:
            pass
    
    def _receive_json(self) -> dict:
        """Receive JSON data from socket"""
        try:
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
        except:
            return {}

def main():
    server = SecureChatServer()
    server.start()

if __name__ == "__main__":
    main()
