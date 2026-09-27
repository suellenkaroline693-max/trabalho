// Monta o texto do cabeçalho Set-Cookie para o cookie temporário de transação
export function buildTransactionCookie(value) {
  return `__Host-oauth-tx=${value}; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=600`;
}

// Monta o texto do cabeçalho Set-Cookie para o cookie de sessão final
export function buildSessionCookie(value) {
  return `__Host-session=${value}; Path=/; HttpOnly; Secure; SameSite=Strict; Max-Age=28800`;
}

// Monta o texto para apagar um cookie (usado no logout ou ao limpar a transação)
export function buildExpiredCookie(name) {
  return `${name}=; Path=/; HttpOnly; Secure; SameSite=Lax; Max-Age=0`;
}

// Lê o valor de um cookie específico a partir do cabeçalho Cookie da requisição
export function readCookie(request, name) {
  const cookieHeader = request.headers.get("Cookie") || "";
  const cookies = cookieHeader.split(";").map((c) => c.trim());
  for (const cookie of cookies) {
    const [key, ...rest] = cookie.split("=");
    if (key === name) {
      return rest.join("=");
    }
  }
  return null;
}
