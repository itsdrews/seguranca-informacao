
import { getSavedIdentity } from "./identity";
import { importPublicKey, deriveSharedSecret } from "./ecdh";
import { deriveKeys } from "./kdf";
import { encryptBlowfish, decryptBlowfish } from "./blowfish";
import { signMessage, verifyMessage } from "./hmac";
import { getPublicKey } from "../services/api";

// Converte bytes para Base64
function toBase64(bytes: Uint8Array): string {
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  return btoa(binary);
}

// Converte Base64 para bytes
function fromBase64(value: string): Uint8Array<ArrayBuffer> {
  const binary = atob(value);
  const bytes = new Uint8Array(binary.length);

  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }

  return bytes;
}

// Obtém as chaves compartilhadas com outro usuário
async function getSessionKeys(
  currentUser: string,
  peerUser: string
) {
  const identity = await getSavedIdentity(currentUser);

  if (!identity) {
    throw new Error("Identidade local não encontrada.");
  }

  const peerKeyBase64 = await getPublicKey(peerUser);

  if (!peerKeyBase64) {
    throw new Error("Chave pública do destinatário indisponível.");
  }

  const peerPublicKey = await importPublicKey(
    fromBase64(peerKeyBase64).buffer
  );

  const sharedSecret = await deriveSharedSecret(
    identity.privateKey,
    peerPublicKey
  );

  return deriveKeys(sharedSecret);
}

// Criptografa uma mensagem antes do envio
export async function encryptMessage(
  currentUser: string,
  recipient: string,
  text: string
): Promise<string> {
  const { cipherKey, macKey } = await getSessionKeys(
    currentUser,
    recipient
  );

  const timestamp = new Date().toLocaleTimeString("pt-BR", {
    hour: "2-digit",
    minute: "2-digit",
    second: "2-digit",
    hour12: false,
  });

  const plaintext = JSON.stringify({
    text,
    timestamp,
  });

  const { iv, ciphertext } = encryptBlowfish(
    plaintext,
    cipherKey
  );

  const tag = await signMessage(iv, ciphertext, macKey);

  const packet = {
    iv: toBase64(iv),
    ciphertext: toBase64(ciphertext),
    tag: toBase64(tag),
  };

  // Formato esperado pelo cliente Python
  return toBase64(
    new TextEncoder().encode(JSON.stringify(packet))
  );
}

// Verifica e descriptografa uma mensagem recebida
export async function decryptMessage(
  currentUser: string,
  sender: string,
  encryptedContent: string
): Promise<{ text: string; timestamp: string }> {
  const { cipherKey, macKey } = await getSessionKeys(
    currentUser,
    sender
  );

  const packetBytes = fromBase64(encryptedContent);
  const packet = JSON.parse(
    new TextDecoder().decode(packetBytes)
  );

  const iv = fromBase64(packet.iv);
  const ciphertext = fromBase64(packet.ciphertext);
  const tag = fromBase64(packet.tag);

  const valid = await verifyMessage(
    iv,
    ciphertext,
    tag,
    macKey
  );

  if (!valid) {
    throw new Error("HMAC inválido: mensagem rejeitada.");
  }

  const plaintext = decryptBlowfish(
    iv,
    ciphertext,
    cipherKey
  );

  const message = JSON.parse(plaintext);

  return {
    text: message.text,
    timestamp: message.timestamp,
  };
}
