"""
keys.py tem como objetico de depósito e busca de chave pública.

Ela possui como comportamentos:
    - Depóstio da pré-chave (Receptor);
    - Busca da chave disponível (Emissor);
"""

from __future__ import annotations

import base64

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

router = APIRouter(prefix="/keys", tags=["keys"])

_public_key_store: dict[str, bytes] = {}


class PublicKeyPayload(BaseModel):
    public_key: str


@router.post("/{user_id}", status_code=201)
def deposit_public_key(user_id: str, payload: PublicKeyPayload) -> dict:
    # Receptor deposita sua PubK_B no servidor
    try:
        raw = base64.b64decode(payload.public_key)
    except Exception:
        raise HTTPException(status_code=400, detail="public_key inválida (base64 malformado)")

    _public_key_store[user_id] = raw
    return {"status": "deposited", "user_id": user_id}


@router.get("/{user_id}", response_model=PublicKeyPayload)
def get_public_key(user_id: str) -> PublicKeyPayload:
    # Emissor busca a PubK_B disponível
    raw = _public_key_store.get(user_id)
    if raw is None:
        raise HTTPException(status_code=404, detail="Nenhuma chave pública depositada para esse usuário")

    return PublicKeyPayload(public_key=base64.b64encode(raw).decode("ascii"))