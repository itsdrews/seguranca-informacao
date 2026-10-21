
const WS_URL = "ws://127.0.0.1:8000/ws";

export function connectWebSocket(
  userId: string,
  onMessage: (data: Record<string, unknown>) => void
): WebSocket {
  const socket = new WebSocket(
    `${WS_URL}/${encodeURIComponent(userId)}`
  );

  socket.onopen = () => {
    console.log("WebSocket conectado:", userId);
  };

  socket.onmessage = (event: MessageEvent) => {
    try {
      const data = JSON.parse(event.data);
      onMessage(data);
    } catch (error) {
      console.error("Erro ao interpretar evento:", error);
    }
  };

  socket.onerror = () => {
    console.error("Erro na conexão WebSocket.");
  };

  socket.onclose = (event) => {
    console.log("WebSocket desconectado:", event.code);
  };

  return socket;
}
