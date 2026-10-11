import asyncio
import base64
from datetime import datetime
import json
import os
import sys
from Crypto.PublicKey import ECC
import requests
import websockets

from crypto.blowfish import BlowfishCipher
from crypto.hmac import MessageAuthenticator
from crypto.kdf import KeyDerivator

HTTP_URL = "http://localhost:8000"
WS_URL = "ws://localhost:8000/ws"


class ChatClient:

  def __init__(self, user_id: str, recipient_id: str):
    self.user_id = user_id
    self.recipient_id = recipient_id

    self.private_key = self._load_or_create_identity_key()
    self.public_key = self.private_key.public_key()

    self.derivator = KeyDerivator(key_len=16)
    self.cipher = BlowfishCipher()
    self.authenticator = MessageAuthenticator()

    self.session_keys: tuple[bytes, bytes] | None = None
    self.local_outbox: list[str] = []

  def _load_or_create_identity_key(self) -> ECC.EccKey:
    key_filename = f"{self.user_id}_private.pem"
    if os.path.exists(key_filename):
      with open(key_filename, "rt") as f:
        return ECC.import_key(f.read())
    else:
      key = ECC.generate(curve="p256")
      with open(key_filename, "wt") as f:
        f.write(key.export_key(format="PEM"))
      return key

  def deposit_public_key(self):
    raw_bytes = self.public_key.export_key(format="DER")
    b64_key = base64.b64encode(raw_bytes).decode("ascii")
    resp = requests.post(
        f"{HTTP_URL}/keys/{self.user_id}", json={"public_key": b64_key}
    )
    resp.raise_for_status()

  def fetch_peer_key(self) -> ECC.EccKey | None:
    try:
      resp = requests.get(f"{HTTP_URL}/keys/{self.recipient_id}")
      if resp.status_code == 200:
        raw_bytes = base64.b64decode(resp.json()["public_key"])
        return ECC.import_key(raw_bytes)
    except Exception:
      pass
    return None

  def try_init_session(self) -> bool:
    peer_pkey = self.fetch_peer_key()
    if peer_pkey:
      from Crypto.Protocol.DH import key_agreement

      def _raw(secret: bytes) -> bytes:
        return secret

      shared_secret = key_agreement(
          eph_priv=self.private_key, eph_pub=peer_pkey, kdf=_raw
      )

      self.session_keys = self.derivator.derive(shared_secret)
      return True
    return False

  def encrypt(self, message: str) -> str:
    cipher_key, mac_key = self.session_keys
    timestamp_str = datetime.now().strftime("%H:%M:%S")

    payload_data = json.dumps({"text": message, "timestamp": timestamp_str})

    iv, ciphertext = self.cipher.encrypt(
        payload_data.encode("utf-8"), cipher_key
    )
    tag = self.authenticator.sign(iv + ciphertext, mac_key)

    packet = {
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }
    return base64.b64encode(json.dumps(packet).encode("utf-8")).decode("ascii")

  def decrypt(self, payload_b64: str) -> tuple[str, str]:
    if not self.session_keys:
      if not self.try_init_session():
        raise ValueError("Chave pública do destinatário indisponível.")

    cipher_key, mac_key = self.session_keys
    raw_json = base64.b64decode(payload_b64).decode("utf-8")
    packet = json.loads(raw_json)

    iv = base64.b64decode(packet["iv"])
    ciphertext = base64.b64decode(packet["ciphertext"])
    tag = base64.b64decode(packet["tag"])

    if not self.authenticator.verify(iv + ciphertext, mac_key, tag):
      raise ValueError("Falha de autenticação HMAC! Mensagem adulterada.")

    decrypted_bytes = self.cipher.decrypt(iv, ciphertext, cipher_key)
    data = json.loads(decrypted_bytes.decode("utf-8"))

    return data["text"], data.get(
        "timestamp", datetime.now().strftime("%H:%M:%S")
    )


async def flush_outbox(ws, client: ChatClient):
  if not client.session_keys or not client.local_outbox:
    return

  now_time = datetime.now().strftime("%H:%M:%S")
  print(
      f"\r[{now_time}] 🚀 [SISTEMA] Enviando {len(client.local_outbox)}"
      " mensagem(ns) pendente(s)...\n> ",
      end="",
      flush=True,
  )
  for msg_text in client.local_outbox:
    encrypted = client.encrypt(msg_text)
    payload = {
        "recipient_id": client.recipient_id,
        "encrypted_content": encrypted,
    }
    await ws.send(json.dumps(payload))

  client.local_outbox.clear()


async def receive_loop(ws, client: ChatClient):
  async for raw_msg in ws:
    data = json.loads(raw_msg)
    event_type = data.get("type")
    now_time = datetime.now().strftime("%H:%M:%S")

    if (
        event_type == "USER_CONNECTED"
        and data.get("user_id") == client.recipient_id
    ):
      print(
          f"\r[{now_time}] 🟢 [SISTEMA] {client.recipient_id} conectou-se.\n> ",
          end="",
          flush=True,
      )
      client.try_init_session()
      await flush_outbox(ws, client)
      continue

    if (
        event_type == "USER_DISCONNECTED"
        and data.get("user_id") == client.recipient_id
    ):
      print(
          f"\r[{now_time}] 🔴 [SISTEMA] {client.recipient_id}"
          " desconectou-se.\n> ",
          end="",
          flush=True,
      )
      continue

    sender = data.get("sender_id")
    encrypted_content = data.get("encrypted_content")

    if sender and encrypted_content:
      try:
        text, msg_time = client.decrypt(encrypted_content)
        print(f"\r[{msg_time}] {sender} diz: {text}\n> ", end="", flush=True)
      except Exception as e:
        print(
            f"\r[{now_time}] ⚠️ Falha ao decifrar mensagem de {sender}: {e}\n> ",
            end="",
            flush=True,
        )


async def send_loop(ws, client: ChatClient):
  while True:
    msg_text = await asyncio.to_thread(input, "> ")
    if not msg_text.strip():
      continue

    now_time = datetime.now().strftime("%H:%M:%S")
    print(
        f"\033[A\r[{now_time}] {client.user_id} diz: {msg_text}\n> ",
        end="",
        flush=True,
    )

    if not client.session_keys:
      if client.try_init_session():
        await flush_outbox(ws, client)
        encrypted = client.encrypt(msg_text)
        await ws.send(
            json.dumps({
                "recipient_id": client.recipient_id,
                "encrypted_content": encrypted,
            })
        )
      else:
        client.local_outbox.append(msg_text)
        print(
            f"\r[{now_time}] ⏳ [Aguardando chave de {client.recipient_id}] Na"
            f" fila local ({len(client.local_outbox)} pendentes).\n> ",
            end="",
            flush=True,
        )
    else:
      encrypted = client.encrypt(msg_text)
      await ws.send(
          json.dumps({
              "recipient_id": client.recipient_id,
              "encrypted_content": encrypted,
          })
      )


async def main():
  if len(sys.argv) < 3:
    print("Uso: python cli_chat.py <seu_usuario> <destinatario>")
    return

  user_id = sys.argv[1]
  recipient_id = sys.argv[2]

  client = ChatClient(user_id, recipient_id)

  print(f"🔄 Sincronizando chave pública de '{user_id}' com o servidor...")
  client.deposit_public_key()

  if client.try_init_session():
    print(f"🔑 Sessão estabelecida com '{recipient_id}'!")
  else:
    print(
        f"⚠️ Chave de '{recipient_id}' não encontrada. Mensagens serão"
        " retidas localmente."
    )

  print(f"\n💬 Chat iniciado entre [{user_id}] e [{recipient_id}]:\n")

  uri = f"{WS_URL}/{user_id}"

  try:
    async with websockets.connect(uri) as ws:
      await asyncio.gather(receive_loop(ws, client), send_loop(ws, client))
  except websockets.exceptions.ConnectionClosedError as e:
    if e.rcvd and e.rcvd.code == 4003:
      print(f"\n❌ [ACESSO NEGADO] {e.rcvd.reason}")
    else:
      print(f"\n🔌 Conexão encerrada pelo servidor: {e}")
  except websockets.exceptions.ConnectionClosedOK:
    print("\n👋 Conexão encerrada.")


if __name__ == "__main__":
  try:
    asyncio.run(main())
  except KeyboardInterrupt:
    print("\n👋 Chat encerrado.")