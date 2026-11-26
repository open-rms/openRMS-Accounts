// openRMS-Accounts' own API (same origin). Spec: openRMS-Spec/accounts/identity.md.
export interface Club {
  id: string; name: string; callsign: string; verified: boolean; myRole: "owner" | "admin" | "member";
  members: { userId: string; callsign: string; name: string; role: "owner" | "admin" | "member" }[];
}
export interface Me {
  user: { id: string; name: string; email: string; callsign: string; role: string; twoFactorEnabled: boolean; passkeys: number } | null;
  permissions?: Record<string, string[]>;
  staffNeedsSecondFactor?: boolean;
  storedRole?: string;
}
export interface ApiKey {
  jti: string; aud: string; scopes: string[]; name: string; created_at: string; expires_at: string; last_used_at: string | null;
  revoked_at: string | null; revoke_reason: string | null; renewable: boolean; client_id: string | null; replaces: string | null; replaced_by: string | null;
}
export interface KeyService { aud: string; name: string; scopes: { scope: string; description: string }[] }
export interface UiConfig { issuer: string; apps: { origin: string; name: string }[] }

async function send<T>(path: string, init: RequestInit = {}): Promise<T> {
  const headers = new Headers(init.headers);
  if (init.body && !headers.has("content-type")) headers.set("content-type", "application/json");
  const res = await fetch(path, { ...init, headers, credentials: "include" });
  if (res.status === 204) return undefined as T;
  const body = await res.json().catch(() => ({}));
  if (!res.ok) throw new Error(body.error_description ?? body.message ?? body.error ?? `HTTP ${res.status}`);
  return body as T;
}

export const api = {
  config: () => send<UiConfig>("/api/v1/ui/config"),
  me: () => send<Me>("/api/v1/me"),
  keys: () => send<{ keys: ApiKey[]; services: KeyService[]; canCreate: boolean; defaultDays: number; maxDays: number }>("/api/v1/me/keys"),
  createKey: (k: { aud: string; scopes: string[]; name: string; days: number }) => send<ApiKey & { key: string }>("/api/v1/me/keys", { method: "POST", body: JSON.stringify(k) }),
  revokeKey: (jti: string) => send<void>(`/api/v1/me/keys/${encodeURIComponent(jti)}`, { method: "DELETE" }),
  revokeAllKeys: () => send<{ revoked: number }>("/api/v1/me/keys/revoke-all", { method: "POST", body: "{}" }),
  clubs: () => send<{ clubs: Club[] }>("/api/v1/me/clubs"),
  createClub: (callsign: string, name: string) => send<{ id: string }>("/api/v1/me/clubs", { method: "POST", body: JSON.stringify({ callsign, name }) }),
  addClubMember: (id: string, callsign: string, role: string) =>
    send<{ ok: true }>(`/api/v1/me/clubs/${id}/members`, { method: "POST", body: JSON.stringify({ callsign, role }) }),
  setClubRole: (id: string, userId: string, role: string) =>
    send<{ ok: true }>(`/api/v1/me/clubs/${id}/members/${userId}`, { method: "PUT", body: JSON.stringify({ role }) }),
  removeClubMember: (id: string, userId: string) => send<void>(`/api/v1/me/clubs/${id}/members/${userId}`, { method: "DELETE" }),
  deleteClub: (id: string) => send<void>(`/api/v1/me/clubs/${id}`, { method: "DELETE" }),
  /** RFC 8628 approval: claim the code for this session, then approve or deny it. */
  device: async (userCode: string, decision: "approve" | "deny") => {
    const code = userCode.trim().toUpperCase().replace(/[^A-Z0-9]/g, "");
    await send(`/api/auth/device?user_code=${encodeURIComponent(code)}`);
    return send(`/api/auth/device/${decision}`, { method: "POST", body: JSON.stringify({ userCode: code }) });
  },
  publicClient: (clientId: string) => send<{ client_id: string; client_name?: string; client_uri?: string; logo_uri?: string }>(
    `/api/auth/oauth2/public-client?client_id=${encodeURIComponent(clientId)}`,
  ),
  consents: () => send<{ clientId: string; scopes: string[] | string; createdAt: string; id: string }[]>("/api/auth/oauth2/get-consents"),
  revokeConsent: (id: string) => send("/api/auth/oauth2/delete-consent", { method: "POST", body: JSON.stringify({ id }) }),
};

let cfg: Promise<UiConfig> | null = null;
export const uiConfig = () => (cfg ??= api.config());

/**
 * Where to go after signing in: a path on this site, or a URL on a trusted openRMS app.
 * Anything else (another site, protocol-relative, javascript:) falls back to /account.
 */
export async function safeNext(raw: string | null): Promise<string> {
  if (!raw) return "/account";
  if (raw.startsWith("/") && !raw.startsWith("//") && !raw.startsWith("/\\")) return raw;
  try {
    const u = new URL(raw);
    const { apps } = await uiConfig();
    if (apps.some((a) => a.origin === u.origin)) return u.href;
  } catch { /* not a URL */ }
  return "/account";
}

export const appName = async (url: string) => {
  try {
    const o = new URL(url, location.origin).origin;
    if (o === location.origin) return null;
    return (await uiConfig()).apps.find((a) => a.origin === o)?.name ?? o;
  } catch {
    return null;
  }
};
