fetch("/api/me", { credentials: "same-origin" })
  .then((response) => (response.ok ? response.json() : null))
  .then((user) => {
    const status = document.getElementById("status");
    status.textContent = user
      ? `Sessão de ${user.email ?? user.displayName}.`
      : "Nenhuma sessão neste navegador.";
  });

document.getElementById("logout-form").addEventListener("submit", async (event) => {
  event.preventDefault();
  await fetch("/oauth/logout", {
    method: "POST",
    credentials: "same-origin",
  });
  window.location.reload();
});
