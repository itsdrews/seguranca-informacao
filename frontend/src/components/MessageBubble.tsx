
export type Message = {
  id: string;
  sender: string;
  text: string;
  timestamp: string;
};

type MessageBubbleProps = {
  message: Message;
  currentUser: string;
};

export default function MessageBubble({
  message,
  currentUser,
}: MessageBubbleProps) {
  const isMine = message.sender === currentUser;

  return (
    <div
      className={`message-row ${
        isMine ? "message-row--mine" : "message-row--theirs"
      }`}
    >
      <div
        className={`message-bubble ${
          isMine ? "message-bubble--mine" : "message-bubble--theirs"
        }`}
      >
        <p className="message-text">{message.text}</p>

        <span className="message-time">
          {message.timestamp}
        </span>
      </div>
    </div>
  );
}