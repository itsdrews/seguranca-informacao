"""
keys.py tem como objetico de depósito e busca de chave pública.

Ela possui como comportamentos:
    - Depósito da pré-chave (Receptor);
    - Busca da chave disponível (Emissor);
"""

from __future__ import annotations
import asyncio
import base64
from database import get_db
import hashlib
from fastapi import APIRouter, HTTPException, Depends, Header
from pydantic import BaseModel
from models.user_public_key_model import UserPublicKeyModel
from schemas import PublicKeyPayload
from sqlalchemy.orm import Session
from routers.websockets_router import manager

router = APIRouter(prefix="/keys", tags=["keys"])


def _fp(data: bytes) -> str:
  h = hashlib.sha256(data).hexdigest()[:16]
  return ":".join(h[i:i + 4] for i in range(0, 16, 4))

@router.get("/", status_code=200)
def list_public_keys(db: Session = Depends(get_db)):
  """Retorna a lista de IDs de todos os usuários que possuem chave depositada."""
  records = db.query(UserPublicKeyModel).all()
  return {"users": [r.user_id for r in records]}

@router.post("/{user_id}", status_code=201)
async def deposit_public_key(
    user_id: str, payload: PublicKeyPayload, db: Session = Depends(get_db)
):
  try:
    raw = base64.b64decode(payload.public_key)
  except Exception:
    raise HTTPException(
        status_code=400, detail="public_key inválida (base64 malformado)"
    )

  record_prev = (
      db.query(UserPublicKeyModel)
      .filter(UserPublicKeyModel.user_id == user_id)
      .first()
  )
  if record_prev is None:
    situacao = "NOVA chave (primeiro cadastro)"
  elif record_prev.public_key == raw:
    situacao = "mesma chave já cadastrada (re-sincronização)"
  else:
    situacao = ("⚠️ CHAVE SUBSTITUÍDA! fp anterior "
                f"{_fp(record_prev.public_key)} -> sessões antigas ficam inválidas")

  # Log detalhado no terminal
  print("\n" + "=" * 60)
  print(f"📥 [DEPÓSITO DE CHAVE] Usuário: '{user_id}'")
  print(f" ├─ Situação           : {situacao}")
  print(f" ├─ Fingerprint        : {_fp(raw)}")
  print(" ├─ O servidor guarda APENAS a chave pública (não vê o segredo ECDH)")
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

  # NOTIFICA OS CLIENTES QUE UMA NOVA CHAVE FOI DEPOSITADA
  await manager.broadcast_event({
      "type": "KEY_DEPOSITED",
      "user_id": user_id,
      "public_key": payload.public_key,
  })
  return {"status": "deposited", "user_id": user_id}


@router.get("/{user_id}", response_model=PublicKeyPayload)
def get_public_key(
    user_id: str,
    db: Session = Depends(get_db),
    x_requester: str | None = Header(default=None),
):
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
  print(f"🔍 [DISTRIBUIÇÃO DE CHAVE] '{x_requester or '?'}' solicitou a chave pública de '{user_id}'")
  print(f" ├─ Finalidade         : '{x_requester or '?'}' fará ECDH local para derivar a sessão {x_requester or '?'}<->{user_id}")
  print(f" ├─ Fingerprint        : {_fp(record.public_key)}")
  print(f" ├─ Tamanho do Payload : {len(record.public_key)} bytes")
  print(f" ├─ Conteúdo (Base64)  : {b64_key}")
  print(f" └─ Conteúdo (Hex Raw) : {record.public_key.hex()}")
  print("=" * 60 + "\n")

  return PublicKeyPayload(public_key=b64_key)