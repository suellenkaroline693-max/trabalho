Testes de segurança e validação do fluxo OAuth 2.0 / OIDC na infraestrutura Cloudflare (Pages + D1).

Caso 1: retorno sem cookie temporário

- Preparação: acesso simulado à URL de callback (/oauth/callback/google ou /oauth/callback/github) em uma janela anônima, sem o cookie seguro e temporário de transação (__Host-oauth-tx) criado no início do fluxo.
- Pedido enviado: requisição de retorno OAuth sem apresentar o cookie __Host-oauth-tx.
- Resultado esperado: a rota de retorno recusa a resposta e não cria sessão.
- Resultado observado: o servidor rejeitou a requisição e retornou HTTP 400 Bad Request, impedindo a conclusão do login sem o estado inicial válido.

Caso 2: state alterado

- Preparação: interceptação do redirecionamento de retorno do provedor, com modificação manual do valor do parâmetro state na URL antes de submeter ao endpoint de callback.
- Pedido enviado: requisição de callback com o parâmetro state alterado em relação ao valor original gerado no início da transação.
- Resultado esperado: a rota de retorno recusa a resposta antes de trocar o código.
- Resultado observado: a validação do parâmetro state falhou ao comparar com o valor armazenado no cookie de transação, resultando na rejeição imediata da tentativa de autenticação (proteção contra CSRF confirmada).

Caso 3: reutilização da transação

- Preparação: cópia da URL de callback completa (com o parâmetro code) logo após a conclusão de um primeiro login bem-sucedido.
- Pedido enviado: nova submissão da mesma URL de callback, reutilizando o código de autorização já consumido.
- Resultado esperado: a transação já foi removida e a repetição deve falhar.
- Resultado observado: o endpoint de callback respondeu com erro HTTP 400 (solicitação malformada/ilegal), confirmando o uso único (single-use) dos códigos de autorização e das transações.

Caso 4: sessão expirada

- Preparação: sessão ativa criada normalmente; em seguida, execução do comando SQL UPDATE sessions SET expires_at = 0; no console do Cloudflare D1.
- Pedido enviado: recarregamento da página, que consulta a rota /api/me com o cookie de sessão ainda presente no navegador.
- Resultado esperado: /api/me deve responder 401.
- Resultado observado: a requisição para /api/me retornou HTTP 401 Unauthorized, e a interface exibiu a mensagem "Nenhuma sessão neste navegador."

Caso 5: origem inválida na saída

- Preparação: sessão válida aberta em URL_BASE; abertura do console do navegador em uma página de origem externa (ex: americanas.com.br).
- Pedido enviado: requisição fetch do tipo POST enviada a partir da origem externa, direcionada ao endpoint /oauth/logout, com credentials: include.
- Resultado esperado: a rota de logout deve recusar a operação.
- Resultado observado: a requisição foi bloqueada pela verificação de origem do servidor e pela política de CORS do navegador, retornando HTTP 403 Forbidden (ERR_FAILED 403). A sessão original permaneceu válida.

 Caso 6: reutilização do cookie revogado

- Preparação: cópia do valor do cookie __Host-session enquanto a sessão estava ativa, através das Ferramentas do Desenvolvedor.
- Pedido enviado: execução do logout normal, seguida da restauração manual do valor antigo do cookie __Host-session e nova consulta a /api/me.
- Resultado esperado: /api/me deve responder 401.
- Resultado observado: ao recarregar a página, /api/me respondeu HTTP 401 Unauthorized, demonstrando que a sessão foi removida do banco D1 e o cookie antigo foi completamente invalidado.
