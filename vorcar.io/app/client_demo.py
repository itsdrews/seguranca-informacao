import base64
import json
import requests
from Crypto.PublicKey import ECC

# Importação dos módulos customizados da pasta crypto/
from crypto.blowfish import BlowfishCipher
from crypto.ecdh import ECDHKeyPair
from crypto.hmac import MessageAuthenticator
from crypto.kdf import KeyDerivator

BASE_URL = "http://localhost:8000"


class CryptoUser:

  def __init__(self, user_id: str):
    self.user_id = user_id

    # Instancia as ferramentas criptográficas
    self.key_pair = ECDHKeyPair.generate(curve="p256")
    self.derivator = KeyDerivator(key_len=16)  # Chaves de 16 bytes (128 bits)
    self.cipher = BlowfishCipher()
    self.authenticator = MessageAuthenticator()

  def get_public_key_b64(self) -> str:
    """Exporta a chave pública ECC em formato DER codificado em Base64."""
    raw_bytes = self.key_pair.public_key.export_key(format="DER")
    return base64.b64encode(raw_bytes).decode("ascii")

  def deposit_public_key(self) -> None:
    """Envia a chave pública para o endpoint POST /keys/{user_id}."""
    payload = {"public_key": self.get_public_key_b64()}
    resp = requests.post(f"{BASE_URL}/keys/{self.user_id}", json=payload)
    resp.raise_for_status()
    print(f"✅ [{self.user_id}] Chave pública depositada no servidor.")

  def fetch_peer_public_key(self, peer_id: str) -> ECC.EccKey:
    """Consulta a chave pública de outro usuário via GET /keys/{peer_id}."""
    resp = requests.get(f"{BASE_URL}/keys/{peer_id}")
    resp.raise_for_status()
    b64_key = resp.json()["public_key"]
    raw_bytes = base64.b64decode(b64_key)
    print(f"🔍 [{self.user_id}] Chave pública de '{peer_id}' obtida do servidor.")
    return ECC.import_key(raw_bytes)

  def derive_session_keys(self, peer_public_key: ECC.EccKey) -> tuple[bytes, bytes]:
    """ECDH + KDF (HKDF): Gera o segredo compartilhado e deriva (cipher_key, mac_key)."""
    shared_secret = self.key_pair.agree(peer_public_key)
    cipher_key, mac_key = self.derivator.derive(shared_secret)
    return cipher_key, mac_key

  def encrypt_and_sign(
      self, cipher_key: bytes, mac_key: bytes, message: str
  ) -> str:
    """Cifra com Blowfish e assina com HMAC (Encrypt-then-MAC)."""
    # 1. Cifragem Blowfish
    iv, ciphertext = self.cipher.encrypt(message.encode("utf-8"), cipher_key)

    # 2. Geração da tag HMAC sobre (IV + Ciphertext)
    tag = self.authenticator.sign(iv + ciphertext, mac_key)

    packet = {
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }
    return base64.b64encode(json.dumps(packet).encode("utf-8")).decode("ascii")

  def verify_and_decrypt(
      self, cipher_key: bytes, mac_key: bytes, payload_b64: str
  ) -> str:
    """Verifica a integridade via HMAC e decifrada com Blowfish."""
    raw_json = base64.b64decode(payload_b64).decode("utf-8")
    packet = json.loads(raw_json)

    iv = base64.b64decode(packet["iv"])
    ciphertext = base64.b64decode(packet["ciphertext"])
    tag = base64.b64decode(packet["tag"])

    # 1. Autenticação HMAC
    if not self.authenticator.verify(iv + ciphertext, mac_key, tag):
      raise ValueError(
          "❌ Falha de Autenticação: A mensagem foi adulterada ou a chave HMAC está incorreta!"
      )

    # 2. Decifragem Blowfish
    plaintext_bytes = self.cipher.decrypt(iv, ciphertext, cipher_key)
    return plaintext_bytes.decode("utf-8")


# =====================================================================
# SIMULAÇÃO DO FLUXO COMPLETO
# =====================================================================
if __name__ == "__main__":
  # Instancia Alice e Bob
  alice = CryptoUser("alice")
  bob = CryptoUser("bob")

  print("\n--- PASSO 1: Depósito de Chaves Públicas ---")
  alice.deposit_public_key()
  bob.deposit_public_key()

  print("\n--- PASSO 2: Alice envia uma mensagem para Bob ---")
  # Alice busca a chave pública de Bob
  bob_pkey = alice.fetch_peer_public_key("bob")

  # Alice calcula ECDH + HKDF -> (cipher_key, mac_key)
  alice_cipher_key, alice_mac_key = alice.derive_session_keys(bob_pkey)

  # Alice cifra com Blowfish e assina com HMAC
  plaintext = "Olá Bob! Mensagem cifrada com Blowfish e autenticada com HMAC."
  encrypted_content = alice.encrypt_and_sign(
      alice_cipher_key, alice_mac_key, plaintext
  )

  # Alice envia para a fila do Redis via API
  msg_payload = {
      "sender_id": "alice",
      "recipient_id": "bob",
      "encrypted_content": encrypted_content,
  }
  requests.post(f"{BASE_URL}/messages/send", json=msg_payload)
  print("📩 Alice enviou a mensagem cifrada para a fila do Redis.")

  print("\n--- PASSO 3: Bob consome e decifra a mensagem ---")
  # Bob consulta mensagens pendentes na fila
  resp = requests.get(f"{BASE_URL}/messages/pending/bob")
  pending_messages = resp.json().get("messages", [])

  # Bob busca a chave pública de Alice
  alice_pkey = bob.fetch_peer_public_key("alice")

  # Bob calcula ECDH + HKDF -> (cipher_key, mac_key)
  bob_cipher_key, bob_mac_key = bob.derive_session_keys(alice_pkey)

  # Bob valida o HMAC e decifra a mensagem
  for msg in pending_messages:
    decrypted_text = bob.verify_and_decrypt(
        bob_cipher_key, bob_mac_key, msg["encrypted_content"]
    )
    print(f"🔓 [Bob leu de {msg['sender_id']}]: '{decrypted_text}'")