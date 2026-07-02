"""
ICrypto implementation using AES-GCM, ported straight from v1's
encrypt_password/decrypt_password/wrap_key/unwrap_key. This adapter
knows nothing about where keys come from -- it just operates on the
bytes it's handed.
"""
from __future__ import annotations

import os

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from core.interfaces import ICrypto


class LocalAesGcmCrypto(ICrypto):
    def generate_key(self) -> bytes:
        return AESGCM.generate_key(bit_length=256)

    def encrypt(self, key: bytes, plaintext: bytes) -> tuple[bytes, bytes]:
        aes = AESGCM(key)
        nonce = os.urandom(12)
        return nonce, aes.encrypt(nonce, plaintext, None)

    def decrypt(self, key: bytes, nonce: bytes, ciphertext: bytes) -> bytes:
        aes = AESGCM(key)
        return aes.decrypt(nonce, ciphertext, None)

    def wrap_key(self, wrapping_key: bytes, key_to_wrap: bytes) -> tuple[bytes, bytes]:
        return self.encrypt(wrapping_key, key_to_wrap)

    def unwrap_key(self, wrapping_key: bytes, nonce: bytes, wrapped: bytes) -> bytes:
        return self.decrypt(wrapping_key, nonce, wrapped)
