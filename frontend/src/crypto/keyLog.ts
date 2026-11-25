/**
 * keyLog.ts - Logs didáticos do ciclo de vida das chaves (console do navegador).
 *
 * Mostra fingerprints (SHA-256 truncado) em vez dos valores secretos,
 * permitindo comparar as chaves dos dois lados da conversa sem expô-las.
 * Os fingerprints são idênticos aos exibidos pelo cliente CLI (cli_chat.py).
 */

export async function fingerprint(
  data: ArrayBuffer | Uint8Array
): Promise<string> {
  const bytes = data instanceof Uint8Array ? data : new Uint8Array(data);
  const digest = await crypto.subtle.digest("SHA-256", bytes.slice());
  const hex = Array.from(new Uint8Array(digest))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("")
    .slice(0, 16);

  return hex.match(/.{4}/g)!.join(":");
}

export function keyLog(user: string, title: string, lines: string[]): void {
  console.groupCollapsed(
    `%c[🔐 ${user}] ${title}`,
    "color:#22c55e;font-weight:bold"
  );
  for (const line of lines) {
    console.log(`  ${line}`);
  }
  console.groupEnd();
}
