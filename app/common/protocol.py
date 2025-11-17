"""Pydantic models: hello, server_hello, register, login, dh_client, dh_server, msg, receipt."""
from pydantic import BaseModel
from typing import Optional

class HelloMessage(BaseModel):
    type: str = "hello"
    client_cert: str  # PEM encoded
    nonce: str  # base64

class ServerHelloMessage(BaseModel):
    type: str = "server_hello"
    server_cert: str  # PEM encoded
    nonce: str  # base64

class RegisterMessage(BaseModel):
    type: str = "register"
    email: str
    username: str
    pwd: str  # base64 encoded SHA256(salt || password)
    salt: str  # base64

class LoginMessage(BaseModel):
    type: str = "login"
    email: str
    pwd: str  # base64 encoded SHA256(salt || password)
    nonce: str  # base64

class DHClientMessage(BaseModel):
    type: str = "dh_client"
    g: int
    p: int
    A: int

class DHServerMessage(BaseModel):
    type: str = "dh_server"
    B: int

class ChatMessage(BaseModel):
    type: str = "msg"
    seqno: int
    ts: int  # unix timestamp in milliseconds
    ct: str  # base64 encoded ciphertext
    sig: str  # base64 encoded signature

class ReceiptMessage(BaseModel):
    type: str = "receipt"
    peer: str  # "client" or "server"
    first_seq: int
    last_seq: int
    transcript_sha256: str  # hex
    sig: str  # base64 encoded signature

class AuthResponse(BaseModel):
    type: str = "auth_response"
    status: str  # "success" or "failure"
    message: Optional[str] = None

class ErrorMessage(BaseModel):
    type: str = "error"
    error: str  # "BAD_CERT", "SIG_FAIL", "REPLAY", etc.
