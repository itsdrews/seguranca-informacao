import { useState } from "react";
import Login from "./pages/Login";
import Chat from "./pages/Chat";
import { logoutUser } from "./services/api";
import "./App.css";

function App() {
  // Recupera o usuário após atualizar a página
  const [username, setUsername] = useState<string | null>(() => {
    return sessionStorage.getItem("currentUser");
  });

  function handleLogin(name: string) {
    sessionStorage.setItem("currentUser", name);
    setUsername(name);
  }

  async function handleLogout() {
    if (!username) return;

    try {
      // Solicita ao backend a exclusão do histórico
      await logoutUser(username);

      // Encerra a sessão local após a confirmação
      sessionStorage.removeItem("currentUser");
      setUsername(null);
    } catch (error) {
      console.error("Erro ao realizar logout:", error);
      alert("Não foi possível encerrar a sessão. Tente novamente.");
    }
  }

  return (
    <>
      {username === null ? (
        <Login onLogin={handleLogin} />
      ) : (
        <Chat
          currentUser={username}
          onLogout={handleLogout}
        />
      )}
    </>
  );
}

export default App;
