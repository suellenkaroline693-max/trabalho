export const PROVIDERS = {
  google: {
    authorizationEndpoint: "https://accounts.google.com/o/oauth2/v2/auth",
    tokenEndpoint: "https://oauth2.googleapis.com/token",
    scope: "openid email profile",
    issuer: "https://accounts.google.com",
    discoveryUrl: "https://accounts.google.com/.well-known/openid-configuration",
  },
  github: {
    authorizationEndpoint: "https://github.com/login/oauth/authorize",
    tokenEndpoint: "https://github.com/login/oauth/access_token",
    userEndpoint: "https://api.github.com/user",
    revokeEndpoint: (clientId) =>
      `https://api.github.com/applications/${clientId}/grant`,
    issuer: "https://github.com",
  },
};

// Confere se o provedor informado na URL é válido (google ou github)
export function isValidProvider(provider) {
  return provider === "google" || provider === "github";
}
