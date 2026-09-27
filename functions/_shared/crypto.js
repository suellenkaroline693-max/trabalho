// Gera um valor aleatório seguro, em texto (Base64URL, sem preenchimento)
export function generateRandomValue() {
  const bytes = new Uint8Array(32);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

// Calcula o "resumo" (hash SHA-256) de um texto, em Base64URL
export async function sha256Base64Url(text) {
  const data = new TextEncoder().encode(text);
  const hashBuffer = await crypto.subtle.digest("SHA-256", data);
  return toBase64Url(new Uint8Array(hashBuffer));
}

// Transforma bytes em texto Base64URL (sem +, /, =)
function toBase64Url(bytes) {
  let binary = "";
  for (const byte of bytes) {
    binary += String.fromCharCode(byte);
  }
  const base64 = btoa(binary);
  return base64.replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}
