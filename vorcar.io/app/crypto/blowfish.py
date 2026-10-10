"""
blowfish.py

Baseado em: Crypto.Cipher.Blowfish (PyCryptodome).
Docs: https://pycryptodome.readthedocs.io/en/stable/src/cipher/blowfish.html
"""

from __future__ import annotations

from abc import ABC, abstractmethod

from Crypto.Cipher import Blowfish
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad



class SymmetricCipher(ABC):
    # Interface para qualquer cifra simétrica usada no pipeline.

    @abstractmethod
    def encrypt(self, plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
        # Retorna (iv, ciphertext)
        raise NotImplementedError

    @abstractmethod
    def decrypt(self, iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
        # Retorna original
        raise NotImplementedError

class BlowfishCipher(SymmetricCipher):

    def __init__(self) -> None:
        self.block_size = Blowfish.block_size  # 8 bytes (64 bits)

    def encrypt(self, plaintext: bytes, key: bytes) -> tuple[bytes, bytes]:
        iv = get_random_bytes(self.block_size)
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        padded = pad(plaintext, self.block_size)
        ciphertext = cipher.encrypt(padded)
        return iv, ciphertext

    def decrypt(self, iv: bytes, ciphertext: bytes, key: bytes) -> bytes:
        cipher = Blowfish.new(key, Blowfish.MODE_CBC, iv)
        padded = cipher.decrypt(ciphertext)
        return unpad(padded, self.block_size)

    def __repr__(self) -> str:
        return f"<BlowfishCipher block_size={self.block_size}>"