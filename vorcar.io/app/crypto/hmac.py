"""
hmac.py - Autenticação de mensagens via HMAC

Baseado em: Crypto.Hash.HMAC (PyCryptodome).
Docs: https://pycryptodome-master.readthedocs.io/en/latest/src/hash/hmac.html
"""

from __future__ import annotations

from Crypto.Hash import HMAC, SHA256


class MessageAuthenticator:
    # Gera e verifica tags HMAC sobre dados
    # já cifrado pelo Blowfish

    def __init__(self, hash_module=SHA256) -> None:
        self.hash_module = hash_module


    # Gera tag de autenticação
    def sign(self, data: bytes, key: bytes) -> bytes:
        h = HMAC.new(key, msg=data, digestmod=self.hash_module)
        return h.digest()


    # Verifica correspondência da tag ao HMAC - 'data' com 'key'
    def verify(self, data: bytes, key: bytes, tag: bytes) -> bool:
        h = HMAC.new(key, msg=data, digestmod=self.hash_module)
        try:
            h.verify(tag)
            return True
        except ValueError:
            return False

    def __repr__(self) -> str:
        return f"<MessageAuthenticator hash={self.hash_module.__name__}>"