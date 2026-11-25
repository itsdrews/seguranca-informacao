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

import hashlib

HTTP_URL = "http://localhost:8000"


def fp(data: bytes) -> str:
  """Impressão digital curta (SHA-256 truncado) - permite comparar chaves
  entre os dois clientes SEM expor o valor secreto no log."""
  h = hashlib.sha256(data).hexdigest()[:16]
  return ":".join(h[i:i + 4] for i in range(0, 16, 4))


def klog(user: str, title: str, lines: list[str]):
  print(f"\r[🔐 {user}] {title}")
  for i, ln in enumerate(lines):
    print(f"   {'└─' if i == len(lines) - 1 else '├─'} {ln}")
  print("> ", end="", flush=True)
WS_URL = "ws://localhost:8000/ws"


class ChatClient:

  def __init__(self, user_id: str):
    self.user_id = user_id

    # Chave Privada Persistente
    self.private_key = self._load_or_create_identity_key()
    self.public_key = self.private_key.public_key()

    self.derivator = KeyDerivator(key_len=16)
    self.cipher = BlowfishCipher()
    self.authenticator = MessageAuthenticator()

    # Dicionário de sessões ativas: { recipient_id: (cipher_key, mac_key) }
    self.sessions: dict[str, tuple[bytes, bytes]] = {}
    # Conjunto de destinatários ativos da conversa atual
    self.active_recipients: set[str] = set()

  def _load_or_create_identity_key(self) -> ECC.EccKey:
    key_filename = f"{self.user_id}_private.pem"
    if os.path.exists(key_filename):
      with open(key_filename, "rt") as f:
        key = ECC.import_key(f.read())
      origem = f"CARREGADA de {key_filename} (identidade já existente)"
    else:
      key = ECC.generate(curve="p256")
      with open(key_filename, "wt") as f:
        f.write(key.export_key(format="PEM"))
      origem = f"CRIADA agora e salva em {key_filename}"
    pub_der = key.public_key().export_key(format="DER")
    klog(self.user_id, "[1. CHAVE CRIADA] Par de chaves ECDH P-256 (identidade)", [
        f"Origem              : {origem}",
        f"Chave privada       : permanece SOMENTE neste cliente (nunca enviada)",
        f"Chave pública (fp)  : {fp(pub_der)}",
    ])
    return key

  def deposit_public_key(self):
    raw_bytes = self.public_key.export_key(format="DER")
    b64_key = base64.b64encode(raw_bytes).decode("ascii")
    resp = requests.post(
        f"{HTTP_URL}/keys/{self.user_id}", json={"public_key": b64_key}
    )
    resp.raise_for_status()
    klog(self.user_id, "[2. CHAVE PÚBLICA DEPOSITADA] no servidor", [
        f"POST /keys/{self.user_id} -> HTTP {resp.status_code}",
        f"Fingerprint enviada : {fp(raw_bytes)}",
    ])

  def fetch_server_keys_list(self) -> list[str]:
    """Consulta no servidor a lista de todos os usuários com chave cadastrada."""
    try:
      resp = requests.get(f"{HTTP_URL}/keys/")
      if resp.status_code == 200:
        users = resp.json().get("users", [])
        return [u for u in users if u != self.user_id]
    except Exception as e:
      print(f"❌ Erro ao consultar servidor: {e}")
    return []

  def fetch_peer_key(self, peer_id: str) -> ECC.EccKey | None:
    try:
      resp = requests.get(
          f"{HTTP_URL}/keys/{peer_id}",
          headers={"X-Requester": self.user_id},
      )
      if resp.status_code == 200:
        raw_bytes = base64.b64decode(resp.json()["public_key"])
        return ECC.import_key(raw_bytes)
    except Exception:
      pass
    return None

  def init_session_for(self, peer_id: str) -> bool:
    """Executa ECDH + HKDF para um destinatário específico."""
    peer_pkey = self.fetch_peer_key(peer_id)
    if peer_pkey:
      from Crypto.Protocol.DH import key_agreement

      def _raw(secret: bytes) -> bytes:
        return secret

      shared_secret = key_agreement(
          eph_priv=self.private_key, eph_pub=peer_pkey, kdf=_raw
      )
      cipher_key, mac_key = self.derivator.derive(shared_secret)
      novo = peer_id not in self.sessions
      self.sessions[peer_id] = (cipher_key, mac_key)
      par = " <-> ".join(sorted([self.user_id, peer_id]))
      klog(self.user_id, f"[3. CHAVE COMPARTILHADA] Sessão par-a-par {par}", [
          f"Chave pública de '{peer_id}' obtida do servidor (fp {fp(peer_pkey.export_key(format='DER'))})",
          f"ECDH(priv {self.user_id}, pub {peer_id}) -> segredo de {len(shared_secret)} bytes",
          f"Segredo compartilhado (fp) : {fp(shared_secret)}",
          f"HKDF-SHA256 -> K_cifra Blowfish (fp) : {fp(cipher_key)}",
          f"HKDF-SHA256 -> K_mac   HMAC     (fp) : {fp(mac_key)}",
          ("Sessão NOVA neste cliente" if novo else "Sessão re-derivada")
          + " | o segredo é DETERMINÍSTICO: mesmo par de identidades => mesmo segredo",
          f"Evidência: '{peer_id}' deve exibir os MESMOS fingerprints do lado dele",
      ])
      return True
    return False

  def encrypt_for(self, recipient_id: str, message: str) -> str:
    if recipient_id not in self.sessions:
      if not self.init_session_for(recipient_id):
        raise ValueError(
            f"Não foi possível estabelecer sessão com '{recipient_id}'"
        )

    cipher_key, mac_key = self.sessions[recipient_id]
    timestamp_str = datetime.now().strftime("%H:%M:%S")

    payload_data = json.dumps({"text": message, "timestamp": timestamp_str})
    iv, ciphertext = self.cipher.encrypt(
        payload_data.encode("utf-8"), cipher_key
    )
    tag = self.authenticator.sign(iv + ciphertext, mac_key)
    klog(self.user_id, f"[4. CIFRANDO] para '{recipient_id}'", [
        f"Usando K_cifra {fp(cipher_key)} / K_mac {fp(mac_key)} (sessão {self.user_id}<->{recipient_id})",
        f"IV aleatório: {iv.hex()} | {len(ciphertext)} bytes cifrados | tag HMAC {tag.hex()[:16]}...",
    ])

    packet = {
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }
    return base64.b64encode(json.dumps(packet).encode("utf-8")).decode("ascii")

  def decrypt_from(self, sender_id: str, payload_b64: str) -> tuple[str, str]:
    if sender_id not in self.sessions:
      if not self.init_session_for(sender_id):
        raise ValueError(
            f"Chave pública do remetente '{sender_id}' indisponível."
        )

    cipher_key, mac_key = self.sessions[sender_id]
    raw_json = base64.b64decode(payload_b64).decode("utf-8")
    packet = json.loads(raw_json)

    iv = base64.b64decode(packet["iv"])
    ciphertext = base64.b64decode(packet["ciphertext"])
    tag = base64.b64decode(packet["tag"])

    if not self.authenticator.verify(iv + ciphertext, mac_key, tag):
      raise ValueError("Falha de autenticação HMAC! Mensagem adulterada.")

    decrypted_bytes = self.cipher.decrypt(iv, ciphertext, cipher_key)
    klog(self.user_id, f"[5. DECIFRADO] mensagem de '{sender_id}'", [
        f"HMAC válido com K_mac {fp(mac_key)} -> integridade e autenticidade OK",
        f"Decifrado com K_cifra {fp(cipher_key)} (sessão {sender_id}<->{self.user_id})",
    ])
    data = json.loads(decrypted_bytes.decode("utf-8"))
    return data["text"], data.get(
        "timestamp", datetime.now().strftime("%H:%M:%S")
    )


async def receive_loop(ws, client: ChatClient):
  async for raw_msg in ws:
    data = json.loads(raw_msg)
    event_type = data.get("type")
    now_time = datetime.now().strftime("%H:%M:%S")

    if event_type == "USER_CONNECTED":
      peer = data.get("user_id")
      if peer in client.active_recipients:
        print(
            f"\r[{now_time}] 🟢 [SISTEMA] {peer} conectou-se.\n> ",
            end="",
            flush=True,
        )
      continue

    if event_type == "USER_DISCONNECTED":
      peer = data.get("user_id")
      if peer in client.active_recipients:
        print(
            f"\r[{now_time}] 🔴 [SISTEMA] {peer} desconectou-se.\n> ",
            end="",
            flush=True,
        )
      continue

    sender = data.get("sender_id")
    encrypted_content = data.get("encrypted_content")

    if sender and encrypted_content:
      try:
        text, msg_time = client.decrypt_from(sender, encrypted_content)
        print(f"\r[{msg_time}] {sender} diz: {text}\n> ", end="", flush=True)
      except Exception as e:
        print(
            f"\r[{now_time}] ⚠️ Erro ao decifrar mensagem de {sender}: {e}\n> ",
            end="",
            flush=True,
        )


async def send_loop(ws, client: ChatClient):
  print_help()
  while True:
    input_text = await asyncio.to_thread(input, "> ")
    cmd = input_text.strip()
    if not cmd:
      continue

    # Comandos de Menu
    if cmd.startswith("/keys") or cmd.startswith("/lista"):
      users = client.fetch_server_keys_list()
      print("\n📋 [CHAVES PÚBLICAS DISPONÍVEIS NO SERVIDOR]:")
      if users:
        for u in users:
          status = "🔑 Sessão ativa" if u in client.sessions else "🌐 Disponível"
          print(f" ├─ {u} ({status})")
      else:
        print(" └─ Nenhum outro usuário cadastrado no momento.")
      print("> ", end="", flush=True)

    elif cmd.startswith("/chat "):
      targets = [t.strip() for t in cmd.split(" ")[1:] if t.strip()]
      if not targets:
        print("⚠️ Informe ao menos um destinatário. Ex: /chat bob carol")
      else:
        client.active_recipients = set(targets)
        for t in targets:
          client.init_session_for(t)
        print(
            f"💬 Conversa direcionada para: {', '.join(client.active_recipients)}"
        )
      print("> ", end="", flush=True)

    elif cmd == "/status":
      print(
          f"\n🎯 Destinatários ativos:"
          f" {', '.join(client.active_recipients) if client.active_recipients else 'Nenhum'}"
      )
      print(f"🔑 Sessões derivadas: {', '.join(client.sessions.keys())}\n> ")

    elif cmd == "/ajuda":
      print_help()

    elif cmd in ("/sair", "/exit", "/quit"):
      print("👋 Encerrando sessão...")
      sys.exit(0)

    else:
      # Envio de Mensagem (Para um ou múltiplos destinatários)
      if not client.active_recipients:
        print(
            "⚠️ Nenhum destinatário selecionado. Use '/keys' para ver a lista"
            " e '/chat <usuario>' para iniciar."
        )
        print("> ", end="", flush=True)
        continue

      now_time = datetime.now().strftime("%H:%M:%S")
      print(
          f"\033[A\r[{now_time}] {client.user_id} diz: {cmd}\n> ",
          end="",
          flush=True,
      )

      # Pairwise Fan-Out: Cifra e envia uma cópia individual para cada destinatário
      recipients = sorted(client.active_recipients)
      group_id = None
      if len(recipients) > 1:
        group_id = "grp-" + fp("|".join(sorted(recipients + [client.user_id])).encode())[:9]
        klog(client.user_id, f"[GRUPO {group_id}] Fan-out par-a-par para {len(recipients)} membros", [
            f"Membros: {', '.join(sorted(recipients + [client.user_id]))}",
            "NÃO existe chave de grupo: cada cópia usa a chave do par (remetente<->membro)",
            "Nenhum segredo novo é criado para o grupo; reutiliza as sessões já derivadas",
        ])
      for recipient in recipients:
        try:
          encrypted_content = client.encrypt_for(recipient, cmd)
          payload = {
              "recipient_id": recipient,
              "encrypted_content": encrypted_content,
          }
          if group_id:
            payload["group_id"] = group_id
            payload["group_members"] = sorted(recipients + [client.user_id])
          await ws.send(json.dumps(payload))
        except Exception as e:
          print(
              f"\n❌ Erro ao enviar para {recipient}: {e}\n> ",
              end="",
              flush=True,
          )


def print_help():
  print("\n" + "=" * 50)
  print("📌 COMANDOS DISPONÍVEIS:")
  print(" /keys                  - Lista usuários e chaves do servidor")
  print(" /chat <user1> <user2>  - Inicia chat com um ou mais destinatários")
  print(" /status                - Exibe destinatários e sessões ativas")
  print(" /ajuda                 - Exibe esta mensagem de ajuda")
  print(" /sair                  - Encerra o chat")
  print("=" * 50 + "\n")


async def main():
  if len(sys.argv) < 2:
    print("Uso: python cli_chat.py <seu_usuario>")
    print("Exemplo: python cli_chat.py alice")
    return

  user_id = sys.argv[1]
  client = ChatClient(user_id)

  print(f"🔄 Depositando/sincronizando chave pública de '{user_id}'...")
  client.deposit_public_key()
  print("✅ Chave pública registrada no servidor.")

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