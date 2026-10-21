import base64
import json

import requests
from Crypto.PublicKey import ECC
from Crypto.Protocol.DH import key_agreement

# pipeline de cripto do sistema legítimo
from crypto.blowfish import BlowfishCipher
from crypto.hmac import MessageAuthenticator
from crypto.kdf import KeyDerivator

HTTP_URL = "http://localhost:8000"

# Instâncias compartilhadas
derivator = KeyDerivator(key_len=16)
cipher = BlowfishCipher()
authenticator = MessageAuthenticator()


def deposit_key(user_id: str, pub: ECC.EccKey) -> None:
    b64 = base64.b64encode(pub.export_key(format="DER")).decode("ascii")
    r = requests.post(f"{HTTP_URL}/keys/{user_id}", json={"public_key": b64})
    r.raise_for_status()


def fetch_key(user_id: str) -> ECC.EccKey:
    #Busca a chave pública que ESTIVER no servidor para aquele nome
    r = requests.get(f"{HTTP_URL}/keys/{user_id}") 
    r.raise_for_status()
    raw = base64.b64decode(r.json()["public_key"])
    return ECC.import_key(raw)


def derive_session(my_priv: ECC.EccKey, peer_pub: ECC.EccKey):
    #ECDH + HKDF -> (cipher_key, mac_key). Igual a init_session_for().
    shared = key_agreement(eph_priv=my_priv, eph_pub=peer_pub, kdf=lambda s: s)
    return derivator.derive(shared)  # (cipher_key, mac_key)


def encrypt_packet(session, text: str) -> str:
    #Produz o mesmo pacote base64({iv, ciphertext, tag}) do sistema.
    cipher_key, mac_key = session
    payload = json.dumps({"text": text, "timestamp": "00:00:00"}).encode("utf-8")
    iv, ct = cipher.encrypt(payload, cipher_key)
    tag = authenticator.sign(iv + ct, mac_key)
    packet = {
        "iv": base64.b64encode(iv).decode("ascii"),
        "ciphertext": base64.b64encode(ct).decode("ascii"),
        "tag": base64.b64encode(tag).decode("ascii"),
    }
    return base64.b64encode(json.dumps(packet).encode("utf-8")).decode("ascii")

def decrypt_packet(session, payload_b64: str) -> str:
    #Verifica HMAC e decifra. Igual a decrypt_from().
    cipher_key, mac_key = session
    packet = json.loads(base64.b64decode(payload_b64).decode("utf-8"))
    iv = base64.b64decode(packet["iv"])
    ct = base64.b64decode(packet["ciphertext"])
    tag = base64.b64decode(packet["tag"])
    if not authenticator.verify(iv + ct, mac_key, tag):
        raise ValueError("HMAC inválido")  # não acontece: Sauron tem a mac_key
    data = json.loads(cipher.decrypt(iv, ct, cipher_key).decode("utf-8"))
    return data["text"]


def short(key_bytes: bytes) -> str:
    """Primeiros bytes de uma chave em hex para comparação."""
    return key_bytes.hex()[:24] + "..."

#Demonstração do ataque
def main() -> None:
    print("=" * 64)
    print("ATAQUE 1 — MITM na troca de chaves  (atacante: Sauron)")
    print("=" * 64)

    # 1) Cenário legítimo: Gandalf e Elrond geram seus pares e depositam
    gandalf_priv = ECC.generate(curve="p256")
    elrond_priv = ECC.generate(curve="p256")
    deposit_key("gandalf", gandalf_priv.public_key())
    deposit_key("elrond", elrond_priv.public_key())
    print("\n[1] Gandalf e Elrond depositaram suas chaves reais no servidor.")

    # 2) Sauron entra
    sauron_priv = ECC.generate(curve="p256")

    # Antes de "envenenar", Sauron lê as chaves reais das vítimas
    real_gandalf_pub = fetch_key("gandalf")
    real_elrond_pub = fetch_key("elrond")
    print("[2] Sauron capturou as chaves públicas reais de Gandalf e Elrond.")

    # 2b) Sauron sobrescreve as duas chaves pela própria (pub_S)
    # Nada impede, pois "POST /keys/{nome}"" não exige autenticação
    deposit_key("gandalf", sauron_priv.public_key())
    deposit_key("elrond", sauron_priv.public_key())
    print("[3] Sauron sobrescreveu 'gandalf' e 'elrond' com a PRÓPRIA chave.")
    print("    (envenenamento do diretório de chaves)")

    # 3) Sauron monta as DUAS sessões
    S1 = derive_session(sauron_priv, real_gandalf_pub)  # com Gandalf
    S2 = derive_session(sauron_priv, real_elrond_pub)   # com Elrond

    # 4) Gandalf quer falar com Elrond: busca "elrond" (recebe pub_S!) e deriva.
    gandalf_sees_elrond = fetch_key("elrond")
    gandalf_session = derive_session(gandalf_priv, gandalf_sees_elrond)

    print("\n[4] Prova de que Gandalf fechou sessão com SAURON, não com Elrond:")
    print(f"    cipher_key do Gandalf : {short(gandalf_session[0])}")
    print(f"    cipher_key do Sauron  : {short(S1[0])}")
    print(f"    --> iguais? {gandalf_session[0] == S1[0]}")

    # 5) Gandalf cifra uma mensagem para Elrond
    segredo = "Elrond, o exercito parte ao amanhecer pelo portao norte."
    pacote_gandalf = encrypt_packet(gandalf_session, segredo)
    print(f'\n[5] Gandalf cifrou (acha que e p/ Elrond): "{segredo}"')

    # 6) Sauron intercepta e decifra com S1 e lê o conteúdo
    lido = decrypt_packet(S1, pacote_gandalf)
    print(f'[6] SAURON decifrou e leu: "{lido}"')

    # 7) Sauron recifra com S2 e repassa para o Elrond real
    pacote_para_elrond = encrypt_packet(S2, lido)
    elrond_session = derive_session(elrond_priv, fetch_key("gandalf"))
    recebido = decrypt_packet(elrond_session, pacote_para_elrond)
    print(f'[7] Elrond recebeu normalmente (HMAC valido!): "{recebido}"')

    print("\n" + "=" * 64)
    print("CONCLUSAO: Sauron leu tudo e repassou intacto. O HMAC validou em")
    print("cada trecho porque Sauron possui a mac_key legitima de cada sessao.")
    print("Integridade != autenticidade da chave. Defesa: assinar a pre-key.")
    print("=" * 64)


if __name__ == "__main__":
    main()