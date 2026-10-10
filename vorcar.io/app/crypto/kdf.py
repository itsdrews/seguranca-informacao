"""
Baseado em: Crypto.Protocol.KDF.HKDF (PyCryptodome).
Docs: https://pycryptodome.readthedocs.io/en/stable/src/protocol/kdf.html
"""

from __future__ import annotations

from Crypto.Protocol.KDF import HKDF
from Crypto.Hash import SHA256


class KeyDerivator:
    # Deriva, a partir do segredo compartilhado do ECDH, as chaves 
    # necessárias para o restante do pipeline (cifra + autenticação).

    def __init__(self, hash_module=SHA256, key_len: int = 32) -> None:
        self.hash_module = hash_module
        self.key_len = key_len

    def derive(
        self,
        shared_secret: bytes,
        salt: bytes | None = None,
    ) -> tuple[bytes, bytes]:
        if salt is None:
            salt = b"\x00" * self.hash_module.digest_size

        cipher_key, mac_key = HKDF(
            master=shared_secret,
            key_len=self.key_len,
            salt=salt,
            hashmod=self.hash_module,
            num_keys=2,
        )
        return cipher_key, mac_key

    def __repr__(self) -> str:
        return f"<KeyDerivator hash={self.hash_module.__name__} key_len={self.key_len}>"