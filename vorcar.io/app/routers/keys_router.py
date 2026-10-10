"""
keys.py tem como objetico de depósito e busca de chave pública.

Ela possui como comportamentos:
    - Depósito da pré-chave (Receptor);
    - Busca da chave disponível (Emissor);
"""

from __future__ import annotations

import base64
from database import get_db
from fastapi import APIRouter, HTTPException, Depends
from pydantic import BaseModel
from models.user_public_key_model import UserPublicKeyModel
from schemas import PublicKeyPayload
from sqlalchemy.orm import Session

router = APIRouter(prefix="/keys", tags=["keys"])


@router.post("/{user_id}", status_code=201)
def deposit_public_key(
    user_id: str, payload: PublicKeyPayload, db: Session = Depends(get_db)
):
  try:
    raw = base64.b64decode(payload.public_key)
  except Exception:
    raise HTTPException(
        status_code=400, detail="public_key inválida (base64 malformado)"
    )

  # Log detalhado no terminal
  print("\n" + "=" * 60)
  print(f"📥 [DEPÓSITO DE CHAVE] Usuário: '{user_id}'")
  print(f" ├─ Tamanho do Payload : {len(raw)} bytes")
  print(f" ├─ Conteúdo (Base64)  : {payload.public_key}")
  print(f" └─ Conteúdo (Hex Raw) : {raw.hex()}")
  print("=" * 60 + "\n")

  # Salva ou atualiza a chave no banco SQLite
  record = (
      db.query(UserPublicKeyModel)
      .filter(UserPublicKeyModel.user_id == user_id)
      .first()
  )
  if record:
    record.public_key = raw
  else:
    record = UserPublicKeyModel(user_id=user_id, public_key=raw)
    db.add(record)

  db.commit()
  return {"status": "deposited", "user_id": user_id}


@router.get("/{user_id}", response_model=PublicKeyPayload)
def get_public_key(user_id: str, db: Session = Depends(get_db)):
  record = (
      db.query(UserPublicKeyModel)
      .filter(UserPublicKeyModel.user_id == user_id)
      .first()
  )
  if not record:
    raise HTTPException(
        status_code=404,
        detail="Nenhuma chave pública depositada para esse usuário",
    )

  b64_key = base64.b64encode(record.public_key).decode("ascii")

  # Log detalhado no terminal
  print("\n" + "=" * 60)
  print(f"🔍 [CONSULTA DE CHAVE] Chave obtida para: '{user_id}'")
  print(f" ├─ Tamanho do Payload : {len(record.public_key)} bytes")
  print(f" ├─ Conteúdo (Base64)  : {b64_key}")
  print(f" └─ Conteúdo (Hex Raw) : {record.public_key.hex()}")
  print("=" * 60 + "\n")

  return PublicKeyPayload(public_key=b64_key)