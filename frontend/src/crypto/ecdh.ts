
/**
 * ECDH com curva P-256.
 * Utiliza a Web Crypto API do navegador.
 */

export type ECDHKeyPair = {
  publicKey: CryptoKey;
  privateKey: CryptoKey;
};

// Gera um par de chaves ECDH
export async function generateKeyPair(): Promise<ECDHKeyPair> {
  const keyPair = await crypto.subtle.generateKey(
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    false,
    ["deriveBits"]
  );

  return {
    publicKey: keyPair.publicKey,
    privateKey: keyPair.privateKey,
  };
}

// Exporta a chave pública em formato DER/SPKI
// compatível com o formato usado pelo cliente Python.
export async function exportPublicKey(
  publicKey: CryptoKey
): Promise<ArrayBuffer> {
  return crypto.subtle.exportKey("spki", publicKey);
}

// Importa uma chave pública DER/SPKI
export async function importPublicKey(
  publicKeyData: ArrayBuffer
): Promise<CryptoKey> {
  return crypto.subtle.importKey(
    "spki",
    publicKeyData,
    {
      name: "ECDH",
      namedCurve: "P-256",
    },
    true,
    []
  );
}

// Calcula o segredo compartilhado ECDH
export async function deriveSharedSecret(
  privateKey: CryptoKey,
  peerPublicKey: CryptoKey
): Promise<ArrayBuffer> {
  return crypto.subtle.deriveBits(
    {
      name: "ECDH",
      public: peerPublicKey,
    },
    privateKey,
    256
  );
}
