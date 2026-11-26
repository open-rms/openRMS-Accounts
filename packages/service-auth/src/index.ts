// @openrms/service-auth: what an openRMS service needs to trust openRMS-Accounts.
// Contract: openRMS-Spec/accounts/identity.md (§3 tokens, §4 claims, §5 API keys, §7 webhooks).
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, decodeProtectedHeader, jwtVerify, type JWTPayload } from "jose";

export type ClubRole = "owner" | "admin" | "member";
export type StaffRole = "user" | "moderator" | "admin" | "superadmin";

export interface ClubClaim {
  id: string;
  callsign: string;
  role: ClubRole;
  verified: boolean;
}

/** Claims of an Accounts access token (spec §4). Presence depends on the granted scopes. */
export interface AccessClaims {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat?: number;
  scope: string[];
  /** OAuth client that obtained the token; absent on first-party tokens. */
  client_id?: string;
  name?: string;
  grid?: string | null;
  email?: string;
  email_verified?: boolean;
  callsign?: string;
  callsign_verified?: boolean;
  callsign_verified_method?: string | null;
  clubs?: ClubClaim[];
  /** First-party tokens only. */
  role?: StaffRole;
}

export interface VerifyOptions {
  /** This service's audience, e.g. "https://atlas.openrms.dev". */
  audience: string;
  /** Trusted issuers. Default: OPENRMS_ISSUER (comma-separated). None configured: every token is refused. */
  issuers?: string[];
  /** Allowed clock skew in seconds (default 30). */
  clockTolerance?: number;
}

export class TokenError extends Error {
  constructor(message: string, readonly code: "missing" | "invalid" | "expired" | "untrusted_issuer" | "wrong_audience" | "revoked") {
    super(message);
    this.name = "TokenError";
  }
}

const jwksCache = new Map<string, ReturnType<typeof createRemoteJWKSet>>();
const jwksUriCache = new Map<string, Promise<string>>();

function trim(u: string) {
  return u.replace(/\/+$/, "");
}

export function defaultIssuers(): string[] {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.OPENRMS_ISSUER;
  return (env ?? "").split(",").map((s) => trim(s.trim())).filter(Boolean);
}

/** The issuer's jwks_uri, from OIDC discovery (cached per process). */
async function jwksUri(issuer: string): Promise<string> {
  let p = jwksUriCache.get(issuer);
  if (!p) {
    p = fetch(`${issuer}/.well-known/openid-configuration`)
      .then(async (r) => {
        if (!r.ok) throw new Error(`discovery ${r.status}`);
        const d = (await r.json()) as { jwks_uri?: string };
        if (!d.jwks_uri) throw new Error("discovery has no jwks_uri");
        return d.jwks_uri;
      })
      .catch((e) => {
        jwksUriCache.delete(issuer); // retry next time
        throw e;
      });
    jwksUriCache.set(issuer, p);
  }
  return p;
}

async function keySet(issuer: string) {
  let ks = jwksCache.get(issuer);
  if (!ks) {
    ks = createRemoteJWKSet(new URL(await jwksUri(issuer)), { cooldownDuration: 30_000, cacheMaxAge: 10 * 60_000 });
    jwksCache.set(issuer, ks);
  }
  return ks;
}

/** Prefix and JWT `typ` of an Accounts API key (spec §5.1). */
export const KEY_PREFIX = "ormk_";
export const KEY_TYP = "openrms-key+jwt";

function headerTyp(jwt: string): string | undefined {
  try {
    return decodeProtectedHeader(jwt).typ;
  } catch {
    return undefined;
  }
}

/** Read `Authorization: Bearer <token>`; returns null when absent. */
export function bearerToken(header: string | null | undefined): string | null {
  const m = /^Bearer\s+(.+)$/i.exec(header ?? "");
  return m ? m[1]!.trim() : null;
}

function decodeIss(token: string): string | undefined {
  try {
    const payload = JSON.parse(Buffer.from(token.split(".")[1] ?? "", "base64url").toString("utf8")) as JWTPayload;
    return typeof payload.iss === "string" ? trim(payload.iss) : undefined;
  } catch {
    return undefined;
  }
}

/**
 * Verify an Accounts access token offline against the issuer's JWKS.
 * Checks signature, issuer (must be trusted), audience and expiry; returns the claims.
 * Refuses API keys: use verifyBearer where keys are allowed.
 */
export async function verifyAccessToken(token: string | null | undefined, opts: VerifyOptions): Promise<AccessClaims> {
  if (!token) throw new TokenError("no token", "missing");
  if (token.startsWith(KEY_PREFIX) || headerTyp(token) === KEY_TYP) throw new TokenError("API keys are not accepted here", "invalid");
  const claims = await verifyJwt(token, opts);
  if ((claims as { token_use?: unknown }).token_use === "api_key") throw new TokenError("API keys are not accepted here", "invalid");
  return claims;
}

async function verifyJwt(token: string, opts: VerifyOptions & { typ?: string }): Promise<AccessClaims> {
  const issuers = (opts.issuers ?? defaultIssuers()).map(trim);
  const iss = decodeIss(token);
  if (!iss) throw new TokenError("not a JWT", "invalid");
  if (!issuers.includes(iss)) throw new TokenError(`issuer ${iss} is not trusted`, "untrusted_issuer");
  try {
    const { payload } = await jwtVerify(token, await keySet(iss), {
      issuer: [iss, `${iss}/`],
      audience: opts.audience,
      clockTolerance: opts.clockTolerance ?? 30,
      ...(opts.typ ? { typ: opts.typ } : {}),
    });
    if (typeof payload.sub !== "string" || !payload.sub) throw new TokenError("token has no subject", "invalid");
    const scope = typeof payload.scope === "string" ? payload.scope.split(" ").filter(Boolean) : Array.isArray(payload.scope) ? (payload.scope as string[]) : [];
    return { ...(payload as unknown as AccessClaims), iss, scope };
  } catch (e) {
    if (e instanceof TokenError) throw e;
    const code = (e as { code?: string }).code;
    if (code === "ERR_JWT_EXPIRED") throw new TokenError("token expired", "expired");
    if (code === "ERR_JWT_CLAIM_VALIDATION_FAILED" && (e as { claim?: string }).claim === "aud") {
      throw new TokenError(`token is not for ${opts.audience}`, "wrong_audience");
    }
    throw new TokenError(`invalid token: ${(e as Error).message}`, "invalid");
  }
}

// ---------------------------------------------------------------- API keys (spec §5)

/** Claims of an Accounts API key (spec §5.1). */
export interface KeyClaims {
  iss: string;
  sub: string;
  aud: string;
  exp: number;
  iat?: number;
  jti: string;
  scope: string[];
  token_use: "api_key";
  /** Owner's callsign when the key was minted: display only, key data on `sub`. */
  callsign?: string;
  renewable?: boolean;
  /** On a key made by renewal: the jti it replaces (spec §5.4). */
  replaces?: string;
}

export type Bearer = { kind: "access"; claims: AccessClaims } | { kind: "key"; claims: KeyClaims };

export interface VerifyBearerOptions extends VerifyOptions {
  /** The service's persisted denylist lookup (spec §5.5). Required: keys live for months. */
  isRevoked: (jti: string) => boolean | Promise<boolean>;
}

/**
 * Verify `Authorization: Bearer` that may be an access token or an API key (`ormk_…`).
 * Keys are checked like tokens (offline, JWKS), plus `typ`, `token_use`, a single audience and
 * the denylist. Staff routes must refuse `kind: "key"` (spec §5.2), and every key use should
 * check the owner against the service's account cache (bans).
 */
export async function verifyBearer(token: string | null | undefined, opts: VerifyBearerOptions): Promise<Bearer> {
  if (!token) throw new TokenError("no token", "missing");
  if (!token.startsWith(KEY_PREFIX)) return { kind: "access", claims: await verifyAccessToken(token, opts) };
  const jwt = token.slice(KEY_PREFIX.length);
  const c = (await verifyJwt(jwt, { ...opts, typ: KEY_TYP })) as unknown as KeyClaims & { aud: string | string[] };
  if (c.token_use !== "api_key") throw new TokenError("not an API key", "invalid");
  if (typeof c.jti !== "string" || !c.jti) throw new TokenError("API key has no jti", "invalid");
  if (Array.isArray(c.aud) && c.aud.length !== 1) throw new TokenError("an API key has exactly one audience", "invalid");
  if (await opts.isRevoked(c.jti)) throw new TokenError("API key revoked", "revoked");
  return { kind: "key", claims: { ...c, aud: Array.isArray(c.aud) ? c.aud[0]! : c.aud } };
}

/** A revoked key, as the pull endpoint and the `key.revoked` webhook report it. `exp` is unix seconds. */
export interface RevokedKey {
  jti: string;
  sub: string;
  exp: number;
  revoked_at: string;
}

export interface RevocationSyncOptions {
  /** Default: the first OPENRMS_ISSUER. */
  issuer?: string;
  /** This service's client-credentials id and secret (scope `accounts.keys`). */
  clientId: string;
  clientSecret: string;
  /**
   * Store newly revoked keys in your persisted denylist (idempotent: the same jti can arrive
   * twice, from the webhook and the pull). Also the place to drop rows bound to those keys.
   */
  store: (keys: RevokedKey[]) => Promise<void>;
  /** The newest `revoked_at` you have stored (ISO), or null when empty. Pulls overlap it by 5 minutes. */
  lastSync: () => Promise<string | null>;
  /** Pull interval in ms (default 5 minutes). */
  intervalMs?: number;
  /** Where failures go (default console.error). Sync failures never stop keys working (fail open). */
  log?: (message: string, error?: unknown) => void;
}

/**
 * Keeps a service's API-key denylist current (spec §5.5): `start()` pulls at once and every
 * `intervalMs`; pass every verified webhook event to `ingest()` for the fast path.
 */
export class RevocationSync {
  private timer: ReturnType<typeof setInterval> | undefined;
  private token: { value: string; until: number } | undefined;
  private readonly issuer: string;
  private readonly log: (message: string, error?: unknown) => void;

  constructor(private readonly opts: RevocationSyncOptions) {
    const issuer = opts.issuer ?? defaultIssuers()[0];
    if (!issuer) throw new Error("RevocationSync needs an issuer (OPENRMS_ISSUER)");
    this.issuer = trim(issuer);
    this.log = opts.log ?? ((m, e) => console.error(`[openrms keys] ${m}`, e ?? ""));
  }

  /** First pull, then the timer. Resolves even if the first pull fails (logged). */
  async start(): Promise<void> {
    await this.pull().catch((e) => this.log("revocation pull failed; keys keep working until it succeeds", e));
    this.timer ??= setInterval(() => {
      this.pull().catch((e) => this.log("revocation pull failed; keys keep working until it succeeds", e));
    }, this.opts.intervalMs ?? 5 * 60_000);
    (this.timer as { unref?: () => void }).unref?.();
  }

  stop() {
    if (this.timer) clearInterval(this.timer);
    this.timer = undefined;
  }

  /** Fetch revocations since the last stored one; returns how many were handed to `store`. */
  async pull(): Promise<number> {
    const last = await this.opts.lastSync();
    const since = last ? new Date(new Date(last).getTime() - 5 * 60_000).toISOString() : "1970-01-01T00:00:00.000Z";
    const res = await fetch(`${this.issuer}/api/v1/keys/revoked?since=${encodeURIComponent(since)}`, {
      headers: { authorization: `Bearer ${await this.accessToken()}` },
    });
    if (res.status === 401) this.token = undefined;
    if (!res.ok) throw new Error(`GET /api/v1/keys/revoked: HTTP ${res.status}`);
    const body = (await res.json()) as { revoked: RevokedKey[] };
    if (body.revoked.length) await this.opts.store(body.revoked);
    return body.revoked.length;
  }

  /** Handle a verified webhook event. Returns true for `key.revoked` (stored), false for others. */
  async ingest(event: AccountsEvent): Promise<boolean> {
    if (event.type !== "key.revoked") return false;
    const d = event.data as { jti?: string; sub?: string; exp?: number };
    if (!d.jti || !d.sub || typeof d.exp !== "number") throw new Error("malformed key.revoked event");
    await this.opts.store([{ jti: d.jti, sub: d.sub, exp: d.exp, revoked_at: event.createdAt }]);
    return true;
  }

  private async accessToken(): Promise<string> {
    if (this.token && this.token.until > Date.now() + 30_000) return this.token.value;
    const disc = (await (await fetch(`${this.issuer}/.well-known/openid-configuration`)).json()) as { token_endpoint: string };
    const res = await fetch(disc.token_endpoint, {
      method: "POST",
      headers: {
        "content-type": "application/x-www-form-urlencoded",
        authorization: `Basic ${Buffer.from(`${encodeURIComponent(this.opts.clientId)}:${encodeURIComponent(this.opts.clientSecret)}`).toString("base64")}`,
      },
      body: new URLSearchParams({ grant_type: "client_credentials", resource: this.issuer, scope: "accounts.keys" }).toString(),
    });
    if (!res.ok) throw new Error(`client credentials: HTTP ${res.status} ${await res.text()}`);
    const t = (await res.json()) as { access_token: string; expires_in?: number };
    this.token = { value: t.access_token, until: Date.now() + (t.expires_in ?? 900) * 1000 };
    return t.access_token;
  }
}

/** True when the caller holds `role` or higher in the club (from the token; confirm writes against your cache). */
export function clubRoleAtLeast(claims: Pick<AccessClaims, "clubs">, clubId: string, role: ClubRole): boolean {
  const rank: Record<ClubRole, number> = { member: 0, admin: 1, owner: 2 };
  const c = claims.clubs?.find((x) => x.id === clubId);
  return !!c && rank[c.role] >= rank[role];
}

// ---------------------------------------------------------------- webhooks (spec §7)

export interface AccountsEvent<T = Record<string, unknown>> {
  id: string;
  type: string;
  createdAt: string;
  data: T;
}

/**
 * Verify the `openrms-signature: t=<unix>,v1=<hex hmac-sha256 of "<t>.<rawBody>">` header
 * and parse the event. Rejects signatures older than `toleranceSeconds` (default 300).
 */
export function verifyWebhook(rawBody: string, header: string | null | undefined, secret: string, toleranceSeconds = 300): AccountsEvent {
  const parts = Object.fromEntries((header ?? "").split(",").map((kv) => kv.trim().split("=", 2) as [string, string]));
  const t = Number(parts.t);
  const sig = parts.v1;
  if (!Number.isFinite(t) || !sig) throw new Error("missing or malformed openrms-signature");
  if (Math.abs(Date.now() / 1000 - t) > toleranceSeconds) throw new Error("webhook signature too old");
  const expected = signWebhook(rawBody, secret, t).split("v1=")[1]!;
  const a = Buffer.from(sig, "hex");
  const b = Buffer.from(expected, "hex");
  if (a.length !== b.length || !timingSafeEqual(a, b)) throw new Error("bad webhook signature");
  return JSON.parse(rawBody) as AccountsEvent;
}

/** Build the signature header (used by Accounts, and by tests in services). */
export function signWebhook(rawBody: string, secret: string, t = Math.floor(Date.now() / 1000)): string {
  const v1 = createHmac("sha256", secret).update(`${t}.${rawBody}`).digest("hex");
  return `t=${t},v1=${v1}`;
}

// ---------------------------------------------------------------- service-owned keys (spec §5)

/** Hash an API key the way Better Auth's api-key plugin stores it: base64url(sha256(key)), unpadded. */
export function hashApiKey(key: string): string {
  return createHash("sha256").update(key).digest("base64url");
}
