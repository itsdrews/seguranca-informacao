
import { Blowfish } from "egoroof-blowfish";

/**
 * Blowfish em modo CBC com preenchimento PKCS5/PKCS7.
 * Compatível em parâmetros com o PyCryptodome.
 */

export type EncryptedData = {
  iv: Uint8Array;
  ciphertext: Uint8Array;
};

// Criptografa uma mensagem
export function encryptBlowfish(
  plaintext: string,
  key: Uint8Array
): EncryptedData {
  if (key.length !== 16) {
    throw new Error("A chave Blowfish deve ter 16 bytes.");
  }

  // IV aleatório de 8 bytes
  const iv = crypto.getRandomValues(new Uint8Array(8));

  const cipher = new Blowfish(
    Uint8Array.from(key),
    Blowfish.MODE.CBC,
    Blowfish.PADDING.PKCS5
  );

  cipher.setIv(Uint8Array.from(iv));

  const plaintextBytes = new TextEncoder().encode(plaintext);

  const ciphertext = cipher.encode(
    Uint8Array.from(plaintextBytes)
  );

  return {
    iv,
    ciphertext: new Uint8Array(ciphertext),
  };
}

// Descriptografa uma mensagem
export function decryptBlowfish(
  iv: Uint8Array,
  ciphertext: Uint8Array,
  key: Uint8Array
): string {
  if (key.length !== 16) {
    throw new Error("A chave Blowfish deve ter 16 bytes.");
  }

  if (iv.length !== 8) {
    throw new Error("O IV deve ter 8 bytes.");
  }

  if (ciphertext.length === 0 || ciphertext.length % 8 !== 0) {
    throw new Error("Tamanho do texto cifrado inválido.");
  }

  const cipher = new Blowfish(
    Uint8Array.from(key),
    Blowfish.MODE.CBC,
    Blowfish.PADDING.PKCS5
  );

  cipher.setIv(Uint8Array.from(iv));

  const decrypted = cipher.decode(
    Uint8Array.from(ciphertext),
    Blowfish.TYPE.UINT8_ARRAY
  );

  return new TextDecoder("utf-8", {
    fatal: true,
  }).decode(decrypted);
}
