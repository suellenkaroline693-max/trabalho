import { generateRandomValue, sha256Base64Url } from "../../_shared/crypto.js";
import {
  buildSessionCookie,
  buildExpiredCookie,
  readCookie,
} from "../../_shared/cookies.js";
import { PROVIDERS, isValidProvider } from "../../_shared/providers.js";
import { validateGoogleIdToken } from "../../_shared/oidc.js";

export async function onRequestGet(context) {
  const { params, env, request } = context;
  const provider = params.provider;

  if (!isValidProvider(provider)) {
    return new Response("Not found", { status: 404 });
  }

  const url = new URL(request.url);
  const code = url.searchParams.get("code");
  const state = url.searchParams.get("state");
  const error = url.searchParams.get("error");

  if (error || !code || !state) {
    return new Response("Falha na autenticação", { status: 400 });
  }

  const transactionId = readCookie(request, "__Host-oauth-tx");
  if (!transactionId) {
    return new Response("Transação não encontrada", { status: 400 });
  }

  const transactionIdHash = await sha256Base64Url(transactionId);
  const stateHash = await sha256Base64Url(state);

  // Busca a transação no banco e confere se ainda é válida
  const now = Math.floor(Date.now() / 1000);
  const transaction = await env.DB.prepare(
    `SELECT * FROM oauth_transactions WHERE id_hash = ? AND provider = ? AND expires_at > ?`
  )
    .bind(transactionIdHash, provider, now)
    .first();

  if (!transaction) {
    return new Response("Transação inválida ou expirada", { status: 400 });
  }

  if (transaction.state_hash !== stateHash) {
    return new Response("State inválido", { status: 400 });
  }

  // Apaga a transação imediatamente (não pode ser reutilizada)
  await env.DB.prepare(`DELETE FROM oauth_transactions WHERE id_hash = ?`)
    .bind(transactionIdHash)
    .run();

  const config = PROVIDERS[provider];
  const redirectUri = `${env.PUBLIC_BASE_URL}/oauth/callback/${provider}`;
  const clientId =
    provider === "google" ? env.GOOGLE_CLIENT_ID : env.GITHUB_CLIENT_ID;
  const clientSecret =
    provider === "google" ? env.GOOGLE_CLIENT_SECRET : env.GITHUB_CLIENT_SECRET;

  // Troca o código pelo token
  const tokenResponse = await fetch(config.tokenEndpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/x-www-form-urlencoded",
      Accept: "application/json",
    },
    body: new URLSearchParams({
      client_id: clientId,
      client_secret: clientSecret,
      code,
      redirect_uri: redirectUri,
      grant_type: "authorization_code",
      code_verifier: transaction.code_verifier,
    }),
  });

  if (!tokenResponse.ok) {
    return new Response("Falha ao trocar o código", { status: 400 });
  }

  const tokenData = await tokenResponse.json();

  let issuer, subject, email, displayName;

  if (provider === "google") {
    const payload = await validateGoogleIdToken(
      tokenData.id_token,
      clientId,
      transaction.nonce
    );
    issuer = "https://accounts.google.com";
    subject = payload.sub;
    email = payload.email || null;
    displayName = payload.name || null;
  } else {
    // GitHub: usa o access_token para consultar o perfil
    const userResponse = await fetch(config.userEndpoint, {
      headers: {
        Authorization: `Bearer ${tokenData.access_token}`,
        Accept: "application/vnd.github+json",
        "X-GitHub-Api-Version": "2026-03-10",
        "User-Agent": "oauth-pages-lab",
      },
    });

    if (!userResponse.ok) {
      return new Response("Falha ao consultar perfil do GitHub", {
        status: 400,
      });
    }

    const userData = await userResponse.json();
    issuer = "https://github.com";
    subject = String(userData.id);
    email = userData.email || null;
    displayName = userData.name || userData.login || null;

    // Revoga a autorização concedida à OAuth App
    const credentials = btoa(`${clientId}:${clientSecret}`);
    await fetch(config.revokeEndpoint(clientId), {
      method: "DELETE",
      headers: {
        Authorization: `Basic ${credentials}`,
        Accept: "application/vnd.github+json",
        "Content-Type": "application/json",
      },
      body: JSON.stringify({ access_token: tokenData.access_token }),
    });
  }

  // Cria a sessão local
  const sessionId = generateRandomValue();
  const sessionIdHash = await sha256Base64Url(sessionId);
  const sessionExpiresAt = now + 8 * 60 * 60; // 8 horas

  await env.DB.prepare(
    `INSERT INTO sessions (id_hash, issuer, subject, email, display_name, expires_at, created_at)
     VALUES (?, ?, ?, ?, ?, ?, ?)`
  )
    .bind(sessionIdHash, issuer, subject, email, displayName, sessionExpiresAt, now)
    .run();

  return new Response(null, {
    status: 302,
    headers: [
      ["Location", env.PUBLIC_BASE_URL],
      ["Set-Cookie", buildExpiredCookie("__Host-oauth-tx")],
      ["Set-Cookie", buildSessionCookie(sessionId)],
      ["Cache-Control", "no-store"],
    ],
  });
}
