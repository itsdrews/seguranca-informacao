from __future__ import annotations

from Crypto.PublicKey import ECC
from Crypto.PublicKey.ECC import EccKey
from Crypto.Protocol.DH import key_agreement

import gc


class ECDHKeyPair:

    def __init__(self, curve: str = "p256") -> None:
        self.curve = curve
        self._private_key: EccKey | None = None
        self._public_key: EccKey | None = None


    @classmethod
    def generate(cls, curve: str = "p256") -> "ECDHKeyPair":

        instance = cls(curve)
        instance._private_key = ECC.generate(curve=curve)
        instance._public_key = instance._private_key.public_key()
        return instance


    @property
    def public_key(self) -> EccKey:
        return self._public_key


    def agree(self, peer_public_key: EccKey) -> bytes:
        def _raw(secret: bytes) -> bytes:
            return secret # repassar sem transformar

        return key_agreement(
            eph_priv=self._private_key,
            eph_pub=peer_public_key,
            kdf=_raw,
        )


    def destroy(self) -> None:
        self._private_key = None
        self._public_key = None
        gc.collect()


    def __repr__(self) -> str:
        return (
            f"<ECDHKEYPair curve={self.curve!r} "
            f"has_private={self._private_key is not None}"
        )