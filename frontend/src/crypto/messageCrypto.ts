
import { getSavedIdentity } from "./identity";
import { importPublicKey, deriveSharedSecret } from "./ecdh";
import { deriveKeys } from "./kdf";
import { encryptBlowfish, decryptBlowfish } from "./blowfish";
import { signMessage, verifyMessage } from "./hmac";
import { getPublicKey } from "../services/api";
import { fingerprint, keyLog } from "./keyLog";

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

  const peerKeyBase64 = await getPublicKey(peerUser, currentUser);

  if (!peerKeyBase64) {
    throw new Error("Chave pública do destinatário indisponível.");
  }

  const peerKeyBytes = fromBase64(peerKeyBase64);
  const peerPublicKey = await importPublicKey(peerKeyBytes.buffer);

  const sharedSecret = await deriveSharedSecret(
    identity.privateKey,
    peerPublicKey
  );

  const keys = await deriveKeys(sharedSecret);
  const pair = [currentUser, peerUser].sort().join(" <-> ");
  const cacheKey = `${currentUser}|${peerUser}`;

  // Loga a derivação apenas na primeira vez por par (evita poluir o console)
  if (!loggedSessions.has(cacheKey)) {
    loggedSessions.add(cacheKey);
    keyLog(currentUser, `[3. CHAVE COMPARTILHADA] Sessão par-a-par ${pair}`, [
      `Chave pública de '${peerUser}' obtida do servidor (fp ${await fingerprint(peerKeyBytes)})`,
      `ECDH(priv ${currentUser}, pub ${peerUser}) -> segredo de ${sharedSecret.byteLength} bytes`,
      `Segredo compartilhado (fp) : ${await fingerprint(sharedSecret)}`,
      `HKDF-SHA256 -> K_cifra Blowfish (fp) : ${await fingerprint(keys.cipherKey)}`,
      `HKDF-SHA256 -> K_mac   HMAC     (fp) : ${await fingerprint(keys.macKey)}`,
      "O segredo é DETERMINÍSTICO: mesmo par de identidades => mesmo segredo",
      `Evidência: '${peerUser}' deve exibir os MESMOS fingerprints do lado dele`,
    ]);
  }

  return keys;
}

const loggedSessions = new Set<string>();

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

  keyLog(currentUser, `[4. CIFRANDO] para '${recipient}'`, [
    `Usando K_cifra ${await fingerprint(cipherKey)} / K_mac ${await fingerprint(macKey)} (sessão ${currentUser}<->${recipient})`,
    `IV aleatório: ${Array.from(iv, (b) => b.toString(16).padStart(2, "0")).join("")} | ${ciphertext.length} bytes cifrados`,
  ]);

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

  keyLog(currentUser, `[5. DECIFRADO] mensagem de '${sender}'`, [
    `HMAC válido com K_mac ${await fingerprint(macKey)} -> integridade e autenticidade OK`,
    `Decifrado com K_cifra ${await fingerprint(cipherKey)} (sessão ${sender}<->${currentUser})`,
  ]);

  const message = JSON.parse(plaintext);

  return {
    text: message.text,
    timestamp: message.timestamp,
  };
}
