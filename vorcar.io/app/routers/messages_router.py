from datetime import datetime, timezone
from fastapi import APIRouter
from redis_client import pop_offline_messages, push_offline_message
from schemas import SendMessagePayload

router = APIRouter(prefix="/messages", tags=["messages"])


@router.post("/send", status_code=202)
def send_message(payload: SendMessagePayload):
  msg_data = {
      "sender_id": payload.sender_id,
      "recipient_id": payload.recipient_id,
      "encrypted_content": payload.encrypted_content,
      "timestamp": datetime.now(timezone.utc).isoformat(),
  }

  # Enfileira no Redis para o destinatário consumir
  push_offline_message(payload.recipient_id, msg_data)

  return {"status": "queued", "recipient_id": payload.recipient_id}


@router.get("/pending/{user_id}")
def get_pending_messages(user_id: str):
  # Coleta e limpa todas as mensagens pendentes do usuário
  messages = pop_offline_messages(user_id)
  return {"user_id": user_id, "count": len(messages), "messages": messages}