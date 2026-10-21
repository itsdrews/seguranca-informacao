
import { useEffect, useRef, useState, type FormEvent } from "react";
import MessageBubble, { type Message } from "./MessageBubble";

type ChatWindowProps = {
  currentUser: string;
  selectedContact: string | null;
  messages: Message[];
  onSendMessage: (text: string) => void;
};

export default function ChatWindow({
  currentUser,
  selectedContact,
  messages,
  onSendMessage,
}: ChatWindowProps) {
  const [inputMessage, setInputMessage] = useState("");
  const messagesEndRef = useRef<HTMLDivElement>(null);

  // Rola automaticamente até a mensagem mais recente
  useEffect(() => {
    messagesEndRef.current?.scrollIntoView({
      behavior: "smooth",
    });
  }, [messages, selectedContact]);

  function handleSubmit(event: FormEvent<HTMLFormElement>) {
    event.preventDefault();

    const text = inputMessage.trim();

    if (!text || !selectedContact) {
      return;
    }

    onSendMessage(text);
    setInputMessage("");
  }

  // Tela exibida quando nenhum contato foi selecionado
  if (!selectedContact) {
    return (
      <main className="chat-window chat-empty">
        <div className="empty-chat-content">
          <div className="empty-chat-icon">🔐</div>

          <h2>Chat Seguro</h2>

          <p>
            Selecione um contato para iniciar uma conversa.
          </p>

          <span>
            Suas conversas aparecerão aqui.
          </span>
        </div>
      </main>
    );
  }

  return (
    <main className="chat-window">
      {/* Cabeçalho da conversa */}
      <header className="chat-header">
        <div className="chat-contact">
          <div className="chat-avatar">
            {selectedContact.charAt(0).toUpperCase()}
          </div>

          <div className="chat-contact-info">
            <strong>{selectedContact}</strong>
            <span>Conversa privada</span>
          </div>
        </div>

        <div className="chat-security">
          🔒
          <span>Chat Seguro</span>
        </div>
      </header>

      {/* Área das mensagens */}
      <div className="chat-messages">
        {messages.length === 0 ? (
          <div className="chat-no-messages">
            <div className="no-messages-icon">💬</div>

            <h3>Nenhuma mensagem ainda</h3>

            <p>
              Envie uma mensagem para iniciar a conversa com{" "}
              <strong>{selectedContact}</strong>.
            </p>
          </div>
        ) : (
          <div className="messages-list">
            {messages.map((message) => (
              <MessageBubble
                key={message.id}
                message={message}
                currentUser={currentUser}
              />
            ))}

            <div ref={messagesEndRef} />
          </div>
        )}
      </div>

      {/* Campo de envio */}
      <form className="chat-input-area" onSubmit={handleSubmit}>
        <input
          type="text"
          placeholder="Digite sua mensagem..."
          value={inputMessage}
          onChange={(event) => setInputMessage(event.target.value)}
          maxLength={2000}
        />

        <button
          type="submit"
          className="send-button"
          disabled={!inputMessage.trim()}
          title="Enviar mensagem"
        >
          ➤
        </button>
      </form>
    </main>
  );
}
