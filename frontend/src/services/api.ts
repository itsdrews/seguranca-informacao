
const API_URL = "http://127.0.0.1:8000";

// Tipos das respostas da API
type UsersResponse = {
  users: string[];
};

type PublicKeyResponse = {
  public_key: string;
};

// Busca todos os usuários cadastrados no backend
export async function getUsers(): Promise<string[]> {
  const response = await fetch(`${API_URL}/keys/`);

  if (!response.ok) {
    throw new Error(
      "Não foi possível consultar os usuários do servidor."
    );
  }

  const data: UsersResponse = await response.json();

  return data.users;
}

// Registra a chave pública de um usuário no FastAPI
export async function registerPublicKey(
  userId: string,
  publicKeyBase64: string
): Promise<void> {
  const response = await fetch(
    `${API_URL}/keys/${encodeURIComponent(userId)}`,
    {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
      },
      body: JSON.stringify({
        public_key: publicKeyBase64,
      }),
    }
  );

  if (!response.ok) {
    throw new Error(
      `Erro ao registrar chave pública: ${response.status}`
    );
  }
}

// Consulta a chave pública de um usuário
export async function getPublicKey(
  userId: string
): Promise<string | null> {
  const response = await fetch(
    `${API_URL}/keys/${encodeURIComponent(userId)}`
  );

  // Usuário ainda não possui uma chave cadastrada
  if (response.status === 404) {
    return null;
  }

  if (!response.ok) {
    throw new Error(
      `Erro ao consultar chave pública: ${response.status}`
    );
  }

  const data: PublicKeyResponse = await response.json();

  return data.public_key;
}
