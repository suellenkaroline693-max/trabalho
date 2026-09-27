import { sha256Base64Url } from "../_shared/crypto.js";
import { buildExpiredCookie, readCookie } from "../_shared/cookies.js";

export async function onRequestPost(context) {
  const { env, request } = context;

  const origin = request.headers.get("Origin");
  if (origin !== env.PUBLIC_BASE_URL) {
    return new Response("Origem inválida", {
      status: 403,
      headers: { "Cache-Control": "no-store" },
    });
  }

  const sessionId = readCookie(request, "__Host-session");
  if (sessionId) {
    const sessionIdHash = await sha256Base64Url(sessionId);
    await env.DB.prepare(`DELETE FROM sessions WHERE id_hash = ?`)
      .bind(sessionIdHash)
      .run();
  }

  return new Response(null, {
    status: 204,
    headers: {
      "Set-Cookie": buildExpiredCookie("__Host-session"),
      "Cache-Control": "no-store",
    },
  });
}
