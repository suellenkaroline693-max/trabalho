// Busca o documento de descoberta do Google (onde ele diz onde estão as chaves públicas)
async function getGoogleDiscovery() {
  const response = await fetch(
    "https://accounts.google.com/.well-known/openid-configuration"
  );
  return response.json();
}

// Busca o conjunto de chaves públicas (JWKS) do Google
async function getGoogleJwks(jwksUri) {
  const response = await fetch(jwksUri);
  return response.json();
}

// Decodifica uma parte do JWT (Base64URL) para um objeto JSON
function decodeJwtPart(part) {
  const base64 = part.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const decoded = atob(padded);
  return JSON.parse(decoded);
}

// Converte texto Base64URL em Uint8Array (para verificar a assinatura)
function base64UrlToBytes(str) {
  const base64 = str.replace(/-/g, "+").replace(/_/g, "/");
  const padded = base64 + "=".repeat((4 - (base64.length % 4)) % 4);
  const binary = atob(padded);
  const bytes = new Uint8Array(binary.length);
  for (let i = 0; i < binary.length; i++) {
    bytes[i] = binary.charCodeAt(i);
  }
  return bytes;
}

// Valida o id_token (JWT) recebido do Google. Retorna o "payload" (dados da identidade)
// ou lança um erro se algo estiver errado.
export async function validateGoogleIdToken(idToken, expectedAudience, expectedNonce) {
  const parts = idToken.split(".");
  if (parts.length !== 3) {
    throw new Error("Formato de token inválido");
  }

  const [headerPart, payloadPart, signaturePart] = parts;
  const header = decodeJwtPart(headerPart);
  const payload = decodeJwtPart(payloadPart);

  if (header.alg !== "RS256") {
    throw new Error("Algoritmo inesperado");
  }

  const discovery = await getGoogleDiscovery();
  if (payload.iss !== discovery.issuer && payload.iss !== "https://accounts.google.com") {
    throw new Error("Emissor inválido");
  }

  const jwks = await getGoogleJwks(discovery.jwks_uri);
  const jwk = jwks.keys.find((k) => k.kid === header.kid);
  if (!jwk) {
    throw new Error("Chave pública não encontrada");
  }

  const publicKey = await crypto.subtle.importKey(
    "jwk",
    jwk,
    { name: "RSASSA-PKCS1-v1_5", hash: "SHA-256" },
    false,
    ["verify"]
  );

  const signedData = new TextEncoder().encode(`${headerPart}.${payloadPart}`);
  const signature = base64UrlToBytes(signaturePart);

  const isValid = await crypto.subtle.verify(
    "RSASSA-PKCS1-v1_5",
    publicKey,
    signature,
    signedData
  );

  if (!isValid) {
    throw new Error("Assinatura inválida");
  }

  const now = Math.floor(Date.now() / 1000);
  if (payload.exp < now) {
    throw new Error("Token expirado");
  }
  if (payload.aud !== expectedAudience) {
    throw new Error("Audiência inválida");
  }
  if (payload.nonce !== expectedNonce) {
    throw new Error("Nonce inválido");
  }

  return payload;
}
