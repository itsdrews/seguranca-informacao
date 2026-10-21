
import { encryptMessage, decryptMessage } from "./messageCrypto";

export async function testCrypto(): Promise<void> {
  try {
    const sender = "Carlos";
    const recipient = "Pedro";
    const originalText = "Olá Pedro, mensagem criptografada de Carlos!";

    console.log("🔐 Iniciando teste entre Carlos e Pedro...");

    // Carlos criptografa a mensagem para Pedro
    const encrypted = await encryptMessage(
      sender,
      recipient,
      originalText
    );

    console.log("Mensagem criptografada:", encrypted);

    // Pedro descriptografa a mensagem de Carlos
    const decrypted = await decryptMessage(
      recipient,
      sender,
      encrypted
    );

    console.log("Mensagem original:", originalText);
    console.log("Mensagem descriptografada:", decrypted.text);

    if (decrypted.text === originalText) {
      console.log("✅ Teste Carlos → Pedro concluído com sucesso!");
    } else {
      console.error("❌ As mensagens não correspondem.");
    }
  } catch (error) {
    console.error("❌ Erro no teste criptográfico:", error);
  }
}
