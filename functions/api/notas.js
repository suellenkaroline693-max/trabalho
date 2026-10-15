export async function onRequestGet({ env, request }) {
  const nome = new URL(request.url).searchParams.get("aluno");
  const r = await env.DB.prepare(`SELECT * FROM notas WHERE aluno = '${nome}'`).all();
  return Response.json(r.results);
}
