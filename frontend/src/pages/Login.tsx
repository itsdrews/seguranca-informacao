
import { useState, type FormEvent } from "react";
import { getPublicKey } from "../services/api";
import {
  verifyIdentity,
  registerNewIdentity,
} from "../crypto/identity";

type LoginProps = {
  onLogin: (username: string) => void;
};

export default function Login({ onLogin }: LoginProps) {
  const [username, setUsername] = useState("");
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  async function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const name = username.trim();

    if (!name || loading) return;

    setLoading(true);
    setError(null);

    try {
      // Consulta a identidade cadastrada no backend
      const publicKey = await getPublicKey(name);

      if (publicKey !== null) {
        // Usuário existente: confere a identidade local
        const validIdentity = await verifyIdentity(name);

        if (!validIdentity) {
          setError(
            "Este usuário já está cadastrado, mas sua chave " +
            "não corresponde à identidade salva neste navegador."
          );
          return;
        }

        onLogin(name);
        return;
      }

      // Usuário novo: gera e registra a identidade
      await registerNewIdentity(name);

      // Cadastro concluído: entra no chat
      onLogin(name);
    } catch (err) {
      console.error("Erro ao identificar usuário:", err);

      setError(
        "Não foi possível concluir o cadastro ou a identificação. " +
        "Verifique a conexão com o servidor e tente novamente."
      );
    } finally {
      setLoading(false);
    }
  }

  return (
    <main className="login-page">
      <div className="login-card">
        <div className="login-icon">🔐</div>

        <h1>Chat Seguro</h1>

        <form onSubmit={handleSubmit}>
          <label htmlFor="username">Nome de usuário</label>

          <input
            id="username"
            type="text"
            placeholder="Ex.: alice"
            value={username}
            onChange={(event) => setUsername(event.target.value)}
            maxLength={30}
            disabled={loading}
            required
          />

          {error && (
            <p className="login-error" role="alert">
              {error}
            </p>
          )}

          <button type="submit" disabled={loading}>
            {loading ? "Verificando..." : "Entrar no chat"}
          </button>
        </form>

        <p className="login-footer">🔒</p>
      </div>
    </main>
  );
}
