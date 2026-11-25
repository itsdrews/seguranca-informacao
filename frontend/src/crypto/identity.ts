import { exportPublicKey } from "./ecdh";
import { getPublicKey } from "../services/api";
import { generateKeyPair, type ECDHKeyPair } from "./ecdh";
import { registerPublicKey } from "../services/api";
import { fingerprint, keyLog } from "./keyLog";

const DB_NAME = "chat-seguro-keys";
const STORE_NAME = "identities";

// Abre o banco local do navegador
function openDatabase(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const request = indexedDB.open(DB_NAME, 1);

    request.onupgradeneeded = () => {
      const db = request.result;

      if (!db.objectStoreNames.contains(STORE_NAME)) {
        db.createObjectStore(STORE_NAME);
      }
    };

    request.onsuccess = () => resolve(request.result);
    request.onerror = () => reject(request.error);
  });
}

// Recupera uma identidade ou cria um novo par de chaves
export async function getOrCreateIdentity(
  userId: string
): Promise<ECDHKeyPair> {
  const db = await openDatabase();

  try {
    const saved = await new Promise<ECDHKeyPair | undefined>(
      (resolve, reject) => {
        const transaction = db.transaction(STORE_NAME, "readonly");
        const request = transaction.objectStore(STORE_NAME).get(userId);

        request.onsuccess = () => resolve(request.result);
        request.onerror = () => reject(request.error);
      }
    );

    if (saved) {
      keyLog(userId, "[1. CHAVE CARREGADA] Par ECDH P-256 (identidade existente)", [
        "Origem             : IndexedDB do navegador",
        "Chave privada      : não exportável, permanece SOMENTE neste navegador",
        `Chave pública (fp) : ${await fingerprint(await exportPublicKey(saved.publicKey))}`,
      ]);
      return saved;
    }

    const identity = await generateKeyPair();

    keyLog(userId, "[1. CHAVE CRIADA] Par ECDH P-256 (identidade)", [
      "Origem             : CRIADA agora e salva no IndexedDB",
      "Chave privada      : não exportável, permanece SOMENTE neste navegador",
      `Chave pública (fp) : ${await fingerprint(await exportPublicKey(identity.publicKey))}`,
    ]);

    await new Promise<void>((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, "readwrite");

      transaction.objectStore(STORE_NAME).put(identity, userId);

      transaction.oncomplete = () => resolve();
      transaction.onerror = () => reject(transaction.error);
    });

    return identity;
  } finally {
    db.close();
  }
}

/**
 * Busca a identidade criptográfica armazenada no navegador.
 * Não cria novas chaves caso o usuário não exista.
 */
export async function getSavedIdentity(
  userId: string
): Promise<ECDHKeyPair | null> {
  const db = await openDatabase();

  try {
    return await new Promise<ECDHKeyPair | null>((resolve, reject) => {
      const transaction = db.transaction(STORE_NAME, "readonly");
      const request = transaction.objectStore(STORE_NAME).get(userId);

      request.onsuccess = () => resolve(request.result ?? null);
      request.onerror = () => reject(request.error);
    });
  } finally {
    db.close();
  }
}

export async function verifyIdentity(
  userId: string
): Promise<boolean> {
  // Busca a identidade salva no navegador
  const identity = await getSavedIdentity(userId);

  if (!identity) {
    return false;
  }

  // Busca a chave pública cadastrada no FastAPI
  const serverPublicKey = await getPublicKey(userId);

  if (!serverPublicKey) {
    return false;
  }

  // Exporta a chave pública local
  const publicKeyBuffer = await exportPublicKey(
    identity.publicKey
  );

  // Converte a chave local para Base64
  const bytes = new Uint8Array(publicKeyBuffer);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  const localPublicKey = btoa(binary);

  // Compara as chaves
  return localPublicKey === serverPublicKey;
}

export async function registerNewIdentity(
  userId: string
): Promise<void> {
  // Verifica se o nome já está cadastrado
  const existingKey = await getPublicKey(userId);

  if (existingKey !== null) {
    throw new Error("Este nome de usuário já está cadastrado.");
  }

  // Recupera ou gera o par de chaves ECDH
  const identity = await getOrCreateIdentity(userId);

  // Exporta somente a chave pública
  const publicKeyBuffer = await exportPublicKey(
    identity.publicKey
  );

  // Converte a chave pública para Base64
  const bytes = new Uint8Array(publicKeyBuffer);
  let binary = "";

  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }

  const publicKeyBase64 = btoa(binary);

  // Registra a chave pública no FastAPI
  await registerPublicKey(userId, publicKeyBase64);

  keyLog(userId, "[2. CHAVE PÚBLICA DEPOSITADA] no servidor", [
    `POST /keys/${userId} -> OK`,
    `Fingerprint enviada : ${await fingerprint(publicKeyBuffer)}`,
  ]);
}
