
from datetime import datetime, timezone

from fastapi import APIRouter
from redis_client import (
    pop_offline_messages,
    push_offline_message,
    clear_offline_messages,
)
from schemas import SendMessagePayload
from history_store import save_message, clear_user_history

router = APIRouter(prefix="/messages", tags=["messages"])


@router.post("/send", status_code=202)
def send_message(payload: SendMessagePayload):

    # Salva a mensagem no histórico temporário
    msg_data = save_message({
        "sender_id": payload.sender_id,
        "recipient_id": payload.recipient_id,
        "encrypted_content": payload.encrypted_content,
        "timestamp": datetime.now(timezone.utc).isoformat(),
    })

    # Enfileira no Redis para o destinatário consumir
    push_offline_message(payload.recipient_id, msg_data)

    return {
        "status": "queued",
        "recipient_id": payload.recipient_id,
    }


@router.get("/pending/{user_id}")
def get_pending_messages(user_id: str):

    # Coleta e limpa mensagens pendentes do usuário
    messages = pop_offline_messages(user_id)

    return {
        "user_id": user_id,
        "count": len(messages),
        "messages": messages,
    }


@router.post("/logout/{user_id}")
def logout_user(user_id: str):

    # Apaga o histórico temporário do usuário
    clear_user_history(user_id)

    # Remove mensagens pendentes no Redis
    clear_offline_messages(user_id)

    return {
        "status": "success",
        "message": "Histórico e mensagens pendentes apagados."
    }
