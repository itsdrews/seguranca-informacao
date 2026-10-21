import { useEffect, useRef, useState } from "react";
import Sidebar from "../components/Sidebar";
import ChatWindow from "../components/ChatWindow";
import type { Message } from "../components/MessageBubble";
import { getUsers } from "../services/api";
import { connectWebSocket } from "../services/websocket";
import { encryptMessage, decryptMessage } from "../crypto/messageCrypto";

type ChatProps = {
  currentUser: string;
  onLogout: () => void;
};

type IncomingMessage = {
  sender_id?: string;
  encrypted_content?: string;
  type?: string;
  user_id?: string;
};

export default function Chat({ currentUser, onLogout }: ChatProps) {
  const [contacts, setContacts] = useState<string[]>([]);
  const [selectedContact, setSelectedContact] = useState<string | null>(null);
  const [messages, setMessages] = useState<Record<string, Message[]>>({});
  const [error, setError] = useState<string | null>(null);

  const socketRef = useRef<WebSocket | null>(null);

  // Consulta usuários cadastrados no FastAPI
  useEffect(() => {
    let active = true;

    async function loadContacts() {
      try {
        const users = await getUsers();

        if (!active) return;

        setContacts(
          users.filter(
            (user) =>
              user.toLowerCase() !== currentUser.toLowerCase()
          )
        );
      } catch (err) {
        console.error("Erro ao buscar contatos:", err);

        if (active) {
          setError("Não foi possível carregar os contatos.");
        }
      }
    }

    loadContacts();

    const interval = window.setInterval(loadContacts, 5000);

    return () => {
      active = false;
      window.clearInterval(interval);
    };
  }, [currentUser]);

  // Conecta o usuário ao WebSocket
  useEffect(() => {
    let active = true;

    const socket = connectWebSocket(
      currentUser,
      async (data: IncomingMessage) => {
        if (!active) return;

        if (data.type === "KEY_DEPOSITED") {
          try {
            const users = await getUsers();

            if (active) {
              setContacts(
                users.filter(
                  (user) =>
                    user.toLowerCase() !== currentUser.toLowerCase()
                )
              );
            }
          } catch (err) {
            console.error("Erro ao atualizar contatos:", err);
          }

          return;
        }

        if (data.type === "USER_CONNECTED") {
          console.log("Usuário conectado:", data.user_id);
          return;
        }

        if (data.type === "USER_DISCONNECTED") {
          console.log("Usuário desconectado:", data.user_id);
          return;
        }

        // Recebe mensagem criptografada
        if (data.sender_id && data.encrypted_content) {
          try {
            const decrypted = await decryptMessage(
              currentUser,
              data.sender_id,
              data.encrypted_content
            );

            if (!active) return;

            const newMessage: Message = {
              id: crypto.randomUUID(),
              sender: data.sender_id,
              text: decrypted.text,
              timestamp: decrypted.timestamp,
            };

            setMessages((previous) => ({
              ...previous,
              [data.sender_id!]: [
                ...(previous[data.sender_id!] || []),
                newMessage,
              ],
            }));
          } catch (err) {
            console.error("Erro ao descriptografar mensagem:", err);
            if (active) {
              setError("Não foi possível descriptografar a mensagem.");
            }
          }
        }
      }
    );

    socketRef.current = socket;

    return () => {
      active = false;

      if (socketRef.current === socket) {
        socketRef.current = null;
      }

      socket.close();
    };
  }, [currentUser]);

  const currentMessages = selectedContact
    ? messages[selectedContact] || []
    : [];

  // Criptografa e envia a mensagem pelo WebSocket
  async function handleSendMessage(text: string) {
    const recipient = selectedContact;
    if (!recipient) return;

    const socket = socketRef.current;

    if (!socket || socket.readyState !== WebSocket.OPEN) {
      setError("WebSocket desconectado. Não foi possível enviar.");
      return;
    }

    try {
      const encryptedContent = await encryptMessage(
        currentUser,
        recipient,
        text
      );

      if (socket.readyState !== WebSocket.OPEN) {
        throw new Error("Conexão encerrada durante a criptografia.");
      }

      socket.send(
        JSON.stringify({
          recipient_id: recipient,
          encrypted_content: encryptedContent,
        })
      );

      const newMessage: Message = {
        id: crypto.randomUUID(),
        sender: currentUser,
        text,
        timestamp: new Date().toLocaleTimeString("pt-BR", {
          hour: "2-digit",
          minute: "2-digit",
        }),
      };

      setMessages((previous) => ({
        ...previous,
        [recipient]: [
          ...(previous[recipient] || []),
          newMessage,
        ],
      }));

      setError(null);
    } catch (err) {
      console.error("Erro ao enviar mensagem:", err);
      setError("Não foi possível criptografar ou enviar a mensagem.");
    }
  }

  return (
    <div className="chat-layout">
      <Sidebar
        currentUser={currentUser}
        contacts={contacts}
        selectedContact={selectedContact}
        onSelectContact={setSelectedContact}
        onLogout={onLogout}
      />

      <ChatWindow
        currentUser={currentUser}
        selectedContact={selectedContact}
        messages={currentMessages}
        onSendMessage={handleSendMessage}
      />

      {error && (
        <div
          role="alert"
          style={{
            position: "fixed",
            bottom: 90,
            right: 24,
            padding: 12,
            borderRadius: 8,
            background: "#3b1720",
            color: "#fecaca",
            border: "1px solid #7f1d1d",
          }}
        >
          {error}
        </div>
      )}
    </div>
  );
}
