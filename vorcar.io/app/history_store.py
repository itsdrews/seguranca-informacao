
from collections import defaultdict, deque
from datetime import datetime, timezone


# Limite de 200 mensagens por usuário
MAX_HISTORY = 200

# Histórico temporário armazenado na memória RAM
history = defaultdict(lambda: deque(maxlen=MAX_HISTORY))


def save_message(message: dict):
    """Armazena uma mensagem para os dois participantes."""
    msg = message.copy()

    msg.setdefault(
        "timestamp",
        datetime.now(timezone.utc).isoformat()
    )

    sender = msg["sender_id"]
    recipient = msg["recipient_id"]

    history[sender].append(msg.copy())

    if sender != recipient:
        history[recipient].append(msg.copy())

    return msg


def get_history(user_id: str):
    """Recupera as mensagens da sessão de um usuário."""
    return list(history.get(user_id, []))


def clear_user_history(user_id: str):
    """Apaga o histórico do usuário ao realizar logout."""
    history.pop(user_id, None)
