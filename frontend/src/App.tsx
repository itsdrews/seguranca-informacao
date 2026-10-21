
import { useState } from "react";
import Login from "./pages/Login";
import Chat from "./pages/Chat";
import "./App.css";

function App() {
  const [username, setUsername] = useState<string | null>(null);

  function handleLogin(name: string) {
    setUsername(name);
  }

  function handleLogout() {
    setUsername(null);
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
