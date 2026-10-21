
/**
 * HMAC-SHA256
 *
 * Compatível com o hmac.py do projeto Python.
 * Assina e verifica os dados: IV + ciphertext.
 */

// Importa a chave HMAC
async function importHmacKey(
  key: Uint8Array
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "raw",
    Uint8Array.from(key),
    {
      name: "HMAC",
      hash: "SHA-256",
    },
    false,
    ["sign", "verify"]
  );
}

// Concatena o IV e o texto criptografado
export function combineData(
  iv: Uint8Array,
  ciphertext: Uint8Array
): Uint8Array {
  const combined = new Uint8Array(
    iv.length + ciphertext.length
  );

  combined.set(iv, 0);
  combined.set(ciphertext, iv.length);

  return combined;
}

// Gera a assinatura HMAC
export async function signMessage(
  iv: Uint8Array,
  ciphertext: Uint8Array,
  macKey: Uint8Array
): Promise<Uint8Array> {
  const key = await importHmacKey(macKey);

  const data = combineData(iv, ciphertext);

  const signature = await crypto.subtle.sign(
    "HMAC",
    key,
    Uint8Array.from(data)
  );

  return new Uint8Array(signature);
}

// Verifica a autenticidade da mensagem
export async function verifyMessage(
  iv: Uint8Array,
  ciphertext: Uint8Array,
  tag: Uint8Array,
  macKey: Uint8Array
): Promise<boolean> {
  const key = await importHmacKey(macKey);

  const data = combineData(iv, ciphertext);

  return crypto.subtle.verify(
    "HMAC",
    key,
    Uint8Array.from(tag),
    Uint8Array.from(data)
  );
}