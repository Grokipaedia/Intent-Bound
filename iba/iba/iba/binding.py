"""
Intent-Bound Authorization (IBA) - Cryptographic Binding Module

This module provides unforgeable binding between intents and agent credentials
using Ed25519 digital signatures.

Author: Grokipaedia Research
License: MIT
"""

from dataclasses import dataclass
from typing import Optional
from datetime import datetime
import hashlib
import secrets
import base64

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey
    )
    from cryptography.hazmat.primitives import serialization
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    print("Warning: cryptography library not available. Install with: pip install cryptography")


@dataclass
class IntentToken:
    """
    A cryptographically bound intent token.
    
    This token proves that a specific intent was authorized by a specific user
    and cannot be forged or tampered with.
    """
    intent_hash: str
    signature: str
    public_key: str
    bound_at: str
    algorithm: str = "Ed25519"
    
    def to_dict(self):
        """Convert to dictionary."""
        return {
            "intent_hash": self.intent_hash,
            "signature": self.signature,
            "public_key": self.public_key,
            "bound_at": self.bound_at,
            "algorithm": self.algorithm
        }


class Ed25519Signer:
    """
    Handles Ed25519 digital signature operations for intent binding.
    
    Ed25519 is chosen for:
    - High security (128-bit security level)
    - Fast signature generation and verification
    - Small signature size (64 bytes)
    - Deterministic signatures
    """
    
    def __init__(self):
        if not CRYPTO_AVAILABLE:
            raise ImportError(
                "cryptography library required for Ed25519Signer. "
                "Install with: pip install cryptography"
            )
    
    @staticmethod
    def generate_keypair():
        """Generate a new Ed25519 keypair."""
        private_key = Ed25519PrivateKey.generate()
        public_key = private_key.public_key()
        return private_key, public_key
    
    @staticmethod
    def private_key_to_bytes(private_key: Ed25519PrivateKey) -> bytes:
        """Convert private key to bytes."""
        return private_key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption()
        )
    
    @staticmethod
    def public_key_to_bytes(public_key: Ed25519PublicKey) -> bytes:
        """Convert public key to bytes."""
        return public_key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw
        )
    
    @staticmethod
    def private_key_from_bytes(key_bytes: bytes) -> Ed25519PrivateKey:
        """Load private key from bytes."""
        return Ed25519PrivateKey.from_private_bytes(key_bytes)
    
    @staticmethod
    def public_key_from_bytes(key_bytes: bytes) -> Ed25519PublicKey:
        """Load public key from bytes."""
        return Ed25519PublicKey.from_public_bytes(key_bytes)
    
    @staticmethod
    def sign(private_key: Ed25519PrivateKey, message: bytes) -> bytes:
        """Sign a message with a private key."""
        return private_key.sign(message)
    
    @staticmethod
    def verify(public_key: Ed25519PublicKey, signature: bytes, message: bytes) -> bool:
        """Verify a signature with a public key."""
        try:
            public_key.verify(signature, message)
            return True
        except Exception:
            return False


class IntentBinder:
    """
    Binds intents to user credentials using cryptographic signatures.
    
    This ensures that:
    1. Intents cannot be forged
    2. Intents cannot be tampered with
    3. Intent authorization is provable
    """
    
    def __init__(self):
        self.signer = Ed25519Signer() if CRYPTO_AVAILABLE else None
    
    def bind_intent(self, intent_declaration, private_key: Ed25519PrivateKey) -> IntentToken:
        """
        Create a cryptographically bound intent token.
        
        Args:
            intent_declaration: The IntentDeclaration to bind
            private_key: User's Ed25519 private key
            
        Returns:
            IntentToken with cryptographic proof of authorization
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required for intent binding")
        
        # Get deterministic hash of intent
        intent_hash = intent_declaration.get_deterministic_hash()
        
        # Sign the intent hash
        signature = self.signer.sign(private_key, intent_hash.encode())
        
        # Get public key
        public_key = private_key.public_key()
        
        # Create token
        return IntentToken(
            intent_hash=intent_hash,
            signature=base64.b64encode(signature).decode('utf-8'),
            public_key=base64.b64encode(
                self.signer.public_key_to_bytes(public_key)
            ).decode('utf-8'),
            bound_at=datetime.utcnow().isoformat()
        )
    
    def verify_intent(
        self, 
        intent_token: IntentToken, 
        intent_declaration
    ) -> bool:
        """
        Verify that an intent token matches an intent declaration.
        
        This proves:
        1. The intent hasn't been tampered with
        2. The signature is valid
        3. The intent was authorized by the key holder
        """
        if not CRYPTO_AVAILABLE:
            raise ImportError("cryptography library required for intent verification")
        
        # Recreate hash from current intent
        expected_hash = intent_declaration.get_deterministic_hash()
        
        # Verify hash matches
        if intent_token.intent_hash != expected_hash:
            return False
        
        # Decode signature and public key
        try:
            signature = base64.b64decode(intent_token.signature)
            public_key_bytes = base64.b64decode(intent_token.public_key)
            public_key = self.signer.public_key_from_bytes(public_key_bytes)
        except Exception:
            return False
        
        # Verify signature
        return self.signer.verify(
            public_key,
            signature,
            expected_hash.encode()
        )


class SimpleIntentBinder:
    """
    A simplified intent binder for environments without cryptography library.
    
    WARNING: This uses HMAC-SHA256 instead of Ed25519. It's suitable for
    development/testing but NOT for production use.
    """
    
    def __init__(self, secret_key: Optional[bytes] = None):
        if secret_key is None:
            secret_key = secrets.token_bytes(32)
        self.secret_key = secret_key
    
    def bind_intent(self, intent_declaration, user_id: str) -> IntentToken:
        """Create a simple HMAC-based intent token."""
        import hmac
        
        # Get intent hash
        intent_hash = intent_declaration.get_deterministic_hash()
        
        # Create HMAC signature
        message = f"{intent_hash}:{user_id}".encode()
        signature = hmac.new(self.secret_key, message, hashlib.sha256).hexdigest()
        
        # Create token
        return IntentToken(
            intent_hash=intent_hash,
            signature=signature,
            public_key=user_id,  # Using user_id as "public key"
            bound_at=datetime.utcnow().isoformat(),
            algorithm="HMAC-SHA256"
        )
    
    def verify_intent(
        self,
        intent_token: IntentToken,
        intent_declaration
    ) -> bool:
        """Verify a simple HMAC-based intent token."""
        import hmac
        
        # Recreate hash
        expected_hash = intent_declaration.get_deterministic_hash()
        
        # Verify hash matches
        if intent_token.intent_hash != expected_hash:
            return False
        
        # Recreate signature
        message = f"{expected_hash}:{intent_token.public_key}".encode()
        expected_signature = hmac.new(
            self.secret_key,
            message,
            hashlib.sha256
        ).hexdigest()
        
        # Compare signatures
        return hmac.compare_digest(intent_token.signature, expected_signature)


class IntentVerificationError(Exception):
    """Raised when intent verification fails."""
    pass


# Example usage and testing
if __name__ == "__main__":
    from intent import IntentDeclaration, IntentScope
    
    print("=== Intent Binding Demo ===\n")
    
    # Create an intent
    scope = IntentScope(
        allowed_resources=["calendar:read", "calendar:write"],
        forbidden_resources=["medical_records:*"]
    )
    
    intent = IntentDeclaration(
        intent_id="demo-001",
        declared_purpose="Schedule appointment",
        authorized_by="user@example.com",
        scope=scope
    )
    
    print("Intent Hash:", intent.get_deterministic_hash())
    
    if CRYPTO_AVAILABLE:
        print("\n--- Using Ed25519 (Production) ---")
        
        # Generate keypair
        signer = Ed25519Signer()
        private_key, public_key = signer.generate_keypair()
        
        # Bind intent
        binder = IntentBinder()
        token = binder.bind_intent(intent, private_key)
        
        print("Intent Token:")
        print(f"  Hash: {token.intent_hash[:16]}...")
        print(f"  Signature: {token.signature[:32]}...")
        print(f"  Public Key: {token.public_key[:32]}...")
        print(f"  Bound At: {token.bound_at}")
        
        # Verify intent
        is_valid = binder.verify_intent(token, intent)
        print(f"\nVerification: {'✓ VALID' if is_valid else '✗ INVALID'}")
        
        # Test tampering detection
        print("\n--- Testing Tampering Detection ---")
        intent.declared_purpose = "TAMPERED: Access all records"
        is_valid = binder.verify_intent(token, intent)
        print(f"After tampering: {'✓ VALID' if is_valid else '✗ INVALID (Expected)'}")
    
    else:
        print("\n--- Using HMAC-SHA256 (Development Only) ---")
        print("Install cryptography library for production use:")
        print("  pip install cryptography")
        
        # Use simple binder
        binder = SimpleIntentBinder()
        token = binder.bind_intent(intent, "user@example.com")
        
        print("\nIntent Token:")
        print(f"  Hash: {token.intent_hash[:16]}...")
        print(f"  Signature: {token.signature[:32]}...")
        print(f"  User ID: {token.public_key}")
        print(f"  Algorithm: {token.algorithm}")
        
        # Verify
        is_valid = binder.verify_intent(token, intent)
        print(f"\nVerification: {'✓ VALID' if is_valid else '✗ INVALID'}")
