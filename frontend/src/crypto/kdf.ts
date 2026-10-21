
/**
 * HKDF com SHA-256.
 *
 * Compatível com o kdf.py do backend Python.
 *
 * Gera:
 * - Chave Blowfish: 16 bytes
 * - Chave HMAC: 16 bytes
 */

export type DerivedKeys = {
  cipherKey: Uint8Array;
  macKey: Uint8Array;
};

export async function deriveKeys(
  sharedSecret: ArrayBuffer
): Promise<DerivedKeys> {

  // Importa o segredo compartilhado gerado pelo ECDH
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    sharedSecret,
    "HKDF",
    false,
    ["deriveBits"]
  );

  // O backend Python utiliza 32 bytes zerados como salt
  const salt = new Uint8Array(32);

  // Compatível com o HKDF do PyCryptodome:
  // primeiro 16 bytes para Blowfish,
  // próximos 16 bytes para HMAC.
  const derivedBits = await crypto.subtle.deriveBits(
    {
      name: "HKDF",
      hash: "SHA-256",
      salt,
      info: new Uint8Array(0),
    },
    keyMaterial,
    256
  );

  const derivedBytes = new Uint8Array(derivedBits);

  const cipherKey = derivedBytes.slice(0, 16);
  const macKey = derivedBytes.slice(16, 32);

  return {
    cipherKey,
    macKey,
  };
}
