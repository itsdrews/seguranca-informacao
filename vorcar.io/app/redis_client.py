import json
import redis

# Conexão com o servidor Redis local
redis_client = redis.Redis(
    host="localhost", port=6379, db=0, decode_responses=True
)


def check_redis_connection() -> bool:
  """Verifica se o servidor Redis está respondendo."""
  try:
    return redis_client.ping()
  except redis.ConnectionError:
    return False


def push_offline_message(recipient_id: str, message_data: dict) -> None:
  """Adiciona uma mensagem à fila do destinatário no Redis."""
  queue_key = f"messages:{recipient_id}"
  redis_client.rpush(queue_key, json.dumps(message_data))


def pop_offline_messages(recipient_id: str) -> list[dict]:
  """Busca todas as mensagens pendentes do destinatário e limpa a fila de forma atômica."""
  queue_key = f"messages:{recipient_id}"

  pipeline = redis_client.pipeline()
  pipeline.lrange(queue_key, 0, -1)
  pipeline.delete(queue_key)

  # pipeline.execute() retorna [resultado_lrange, resultado_delete]
  raw_messages, _ = pipeline.execute()

  if not raw_messages:
    return []

  # Converte cada string JSON da lista em dicionário
  return [json.loads(msg) for msg in raw_messages]