import { generateRandomValue, sha256Base64Url } from "../../_shared/crypto.js";
import { buildTransactionCookie } from "../../_shared/cookies.js";
import { PROVIDERS, isValidProvider } from "../../_shared/providers.js";

export async function onRequestGet(context) {
  const { params, env } = context;
  const provider = params.provider;

  if (!isValidProvider(provider)) {
    return new Response("Not found", { status: 404 });
  }

  const config = PROVIDERS[provider];

  // Gera os valores aleatórios que protegem essa transação de login
  const transactionId = generateRandomValue();
  const state = generateRandomValue();
  const codeVerifier = generateRandomValue();
  const nonce = provider === "google" ? generateRandomValue() : null;

  // Calcula os "resumos" que vamos guardar no banco (nunca o valor puro)
  const transactionIdHash = await sha256Base64Url(transactionId);
  const stateHash = await sha256Base64Url(state);

  // PKCE: o code_challenge é o resumo do code_verifier
  const codeChallenge = await sha256Base64Url(codeVerifier);

  const expiresAt = Math.floor(Date.now() / 1000) + 600; // 10 minutos

  // Salva a transação no banco D1
  await env.DB.prepare(
    `INSERT INTO oauth_transactions (id_hash, provider, state_hash, nonce, code_verifier, expires_at)
     VALUES (?, ?, ?, ?, ?, ?)`
  )
    .bind(transactionIdHash, provider, stateHash, nonce, codeVerifier, expiresAt)
    .run();

  // Monta a URL de autorização do provedor
  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
  const clientId =
    provider === "google" ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;

  const authUrl = new URL(config.authorizationEndpoint);
  authUrl.searchParams.set("client_id", clientId);
  authUrl.searchParams.set("redirect_uri", redirectUri);
  authUrl.searchParams.set("response_type", "code");
  authUrl.searchParams.set("state", state);
  authUrl.searchParams.set("code_challenge", codeChallenge);
  authUrl.searchParams.set("code_challenge_method", "S256");

  if (provider === "google") {
    authUrl.searchParams.set("scope", config.scope);
    authUrl.searchParams.set("nonce", nonce);
  }

  return new Response(null, {
    status: 302,
    headers: {
      Location: authUrl.toString(),
      "Set-Cookie": buildTransactionCookie(transactionId),
      "Cache-Control": "no-store",
    },
  });
}
