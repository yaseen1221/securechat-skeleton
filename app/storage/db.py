"""MySQL users table + salted hashing (no chat storage)."""
import pymysql
import os
import hashlib
import secrets
from typing import Optional, Tuple

class Database:
    def __init__(self):
        self.host = os.getenv("DB_HOST", "localhost")
        self.user = os.getenv("DB_USER", "securechat")
        self.password = os.getenv("DB_PASSWORD", "password")
        self.database = os.getenv("DB_NAME", "securechat")
        self.connection = None
    
    def connect(self):
        """Establish database connection"""
        self.connection = pymysql.connect(
            host=self.host,
            user=self.user,
            password=self.password,
            database=self.database,
            charset='utf8mb4',
            cursorclass=pymysql.cursors.DictCursor
        )
    
    def initialize(self):
        """Initialize database schema"""
        self.connect()
        
        with self.connection.cursor() as cursor:
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS users (
                    email VARCHAR(255) PRIMARY KEY,
                    username VARCHAR(100) UNIQUE NOT NULL,
                    salt VARBINARY(16) NOT NULL,
                    pwd_hash CHAR(64) NOT NULL,
                    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                )
            """)
        
        self.connection.commit()
    
    def create_user(self, email: str, username: str, password: str) -> bool:
        """Create a new user with salted password hash"""
        if self.connection is None:
            self.connect()
        
        # Check if user already exists
        with self.connection.cursor() as cursor:
            cursor.execute("SELECT email FROM users WHERE email = %s OR username = %s", 
                         (email, username))
            if cursor.fetchone():
                return False
        
        # Generate salt and hash password
        salt = secrets.token_bytes(16)
        pwd_hash = self._hash_password(password, salt)
        
        # Insert user
        with self.connection.cursor() as cursor:
            cursor.execute(
                "INSERT INTO users (email, username, salt, pwd_hash) VALUES (%s, %s, %s, %s)",
                (email, username, salt, pwd_hash)
            )
        
        self.connection.commit()
        return True
    
    def verify_user(self, email: str, password: str) -> Optional[dict]:
        """Verify user credentials"""
        if self.connection is None:
            self.connect()
        
        with self.connection.cursor() as cursor:
            cursor.execute(
                "SELECT username, salt, pwd_hash FROM users WHERE email = %s",
                (email,)
            )
            result = cursor.fetchone()
            
            if not result:
                return None
            
            # Verify password
            computed_hash = self._hash_password(password, result['salt'])
            if computed_hash == result['pwd_hash']:
                return {'username': result['username']}
            
            return None
    
    def _hash_password(self, password: str, salt: bytes) -> str:
        """Compute SHA256(salt || password)"""
        return hashlib.sha256(salt + password.encode()).hexdigest()
    
    def close(self):
        """Close database connection"""
        if self.connection:
            self.connection.close()

# Singleton instance
db = Database()
