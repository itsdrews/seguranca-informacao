
from datetime import datetime
import json

from fastapi import APIRouter, WebSocket, WebSocketDisconnect
from redis_client import pop_offline_messages, push_offline_message
from history_store import save_message, get_history

router = APIRouter(prefix="/ws", tags=["websocket"])


class ConnectionManager:

    def __init__(self):
        self.active_connections: dict[str, WebSocket] = {}

    def is_user_connected(self, user_id: str) -> bool:
        return user_id in self.active_connections

    async def connect(self, user_id: str, websocket: WebSocket):
        await websocket.accept()
        self.active_connections[user_id] = websocket

    def disconnect(self, user_id: str, websocket: WebSocket):
        if self.active_connections.get(user_id) == websocket:
            del self.active_connections[user_id]

    async def send_personal_message(self, message: dict, user_id: str) -> bool:
        if user_id in self.active_connections:
            await self.active_connections[user_id].send_json(message)
            return True
        return False

    async def broadcast_event(self, event: dict, exclude_user: str | None = None):
        for user_id, connection in list(self.active_connections.items()):
            if user_id != exclude_user:
                try:
                    await connection.send_json(event)
                except Exception:
                    pass


manager = ConnectionManager()


@router.websocket("/{user_id}")
async def websocket_endpoint(websocket: WebSocket, user_id: str):

    # Bloqueio de conexão duplicada
    if manager.is_user_connected(user_id):
        await websocket.accept()
        await websocket.close(
            code=4003,
            reason=(
                f"O usuário '{user_id}' já está conectado em outra instância."
            ),
        )
        return

    await manager.connect(user_id, websocket)
        # Envia o histórico temporário ao usuário
    await websocket.send_json({
        "type": "CHAT_HISTORY",
        "messages": get_history(user_id),
    })

    now = datetime.now().strftime("%H:%M:%S")
    print("\n" + "=" * 60)
    print(f"🟢 [{now}] [CONEXÃO WEBSOCKET] Usuário '{user_id}' conectado.")
    print("=" * 60 + "\n")

    # Notifica os demais usuários da presença
    await manager.broadcast_event(
        {"type": "USER_CONNECTED", "user_id": user_id},
        exclude_user=user_id
    )

    # Entrega mensagens off-line retidas no Redis
    offline_messages = pop_offline_messages(user_id)

    if offline_messages:
        now = datetime.now().strftime("%H:%M:%S")
        print("\n" + "=" * 60)
        print(f"🚀 [{now}] [DESCARGA DE FILA REDIS] Destinatário: '{user_id}'")
        print(
            f" └─ Entregando {len(offline_messages)} mensagem(ns) pendente(s)"
            " cifrada(s) via WS"
        )
        print("=" * 60 + "\n")

        for msg in offline_messages:
            await websocket.send_json(msg)

    try:
        while True:
            data = await websocket.receive_text()
            payload = json.loads(data)

            recipient_id = payload.get("recipient_id")
            encrypted_content = payload.get("encrypted_content", "")

            if (
                not isinstance(recipient_id, str)
                or not recipient_id.strip()
                or not isinstance(encrypted_content, str)
            ):
                continue

            content_length = len(encrypted_content)

            # Trunca o texto cifrado para manter o log legível
            preview = (
                encrypted_content[:50] + "..."
                if content_length > 50
                else encrypted_content
            )

            # NOVO: Armazena a mensagem no histórico temporário
            msg_data = save_message({
                "sender_id": user_id,
                "recipient_id": recipient_id,
                "encrypted_content": encrypted_content,
            })

            # Encaminha a mensagem para o destinatário
            delivered = await manager.send_personal_message(
                msg_data, recipient_id
            )

            now = datetime.now().strftime("%H:%M:%S")

            print("\n" + "=" * 60)

            if delivered:
                print(f"⚡ [{now}] [MENSAGEM ENVIADA - REAL-TIME WS]")
                print(f" ├─ Remetente  : '{user_id}'")
                print(f" ├─ Destino    : '{recipient_id}'")
                print(
                    f" ├─ Tamanho    : {content_length} bytes "
                    "(Payload Cifrado + HMAC)"
                )
                print(f" ├─ Conteúdo   : {preview}")
                print(" └─ Status     : ✅ Entregue diretamente via WebSocket")

            else:
                push_offline_message(recipient_id, msg_data)

                print(f"📦 [{now}] [MENSAGEM ENFILEIRADA - REDIS]")
                print(f" ├─ Remetente  : '{user_id}'")
                print(f" ├─ Destino    : '{recipient_id}' (OFF-LINE)")
                print(
                    f" ├─ Tamanho    : {content_length} bytes "
                    "(Payload Cifrado + HMAC)"
                )
                print(f" ├─ Conteúdo   : {preview}")
                print(
                    f" └─ Status     : 📥 Salva na fila "
                    f"'messages:{recipient_id}' do Redis"
                )

            print("=" * 60 + "\n")

    except WebSocketDisconnect:
        pass

    finally:
        if manager.active_connections.get(user_id) == websocket:
            manager.disconnect(user_id, websocket)

            now = datetime.now().strftime("%H:%M:%S")

            print("\n" + "=" * 60)
            print(
                f"🔴 [{now}] [DESCONEXÃO WEBSOCKET] "
                f"Usuário '{user_id}' desconectado."
            )
            print("=" * 60 + "\n")

            await manager.broadcast_event(
                {"type": "USER_DISCONNECTED", "user_id": user_id},
                exclude_user=user_id,
            )
