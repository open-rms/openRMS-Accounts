// @openrms/service-auth: what an openRMS service needs to trust openRMS-Accounts.
// Contract: openRMS-Spec/accounts/identity.md (§3 tokens, §4 claims, §5 API keys, §7 webhooks).
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JSONWebKeySet, type JWTPayload, type JWTVerifyGetKey } from "jose";

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
  /**
   * File that keeps the last good JWKS, so a restart while Accounts is unreachable still
   * verifies. Default: OPENRMS_JWKS_CACHE_FILE, else memory only.
   */
  jwksCacheFile?: string;
  /** Refresh keys older than this (ms, default 10 minutes). */
  jwksMaxAgeMs?: number;
  /** Least time between fetches, also for an unknown `kid` (ms, default 30 s). */
  jwksCooldownMs?: number;
}

export class TokenError extends Error {
  constructor(message: string, readonly code: "missing" | "invalid" | "expired" | "untrusted_issuer" | "wrong_audience" | "revoked") {
    super(message);
    this.name = "TokenError";
  }
}

function trim(u: string) {
  return u.replace(/\/+$/, "");
}

export function defaultIssuers(): string[] {
  const env = (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.OPENRMS_ISSUER;
  return (env ?? "").split(",").map((s) => trim(s.trim())).filter(Boolean);
}

// ---------------------------------------------------------------- signing keys (JWKS)
//
// Keys are fetched from the issuer's jwks_uri (found by OIDC discovery) and refreshed every
// 10 minutes, or at once (at most every 30 s) when a token names a key we don't have. When a
// refresh fails, the last good set keeps working: an unreachable Accounts must not stop
// verification (spec §5.5). With a cache file (VerifyOptions.jwksCacheFile or
// OPENRMS_JWKS_CACHE_FILE) the last good set also survives a restart.

interface CachedJwks { jwksUri: string; jwks: JSONWebKeySet; fetchedAt: number }
const jwksCache = new Map<string, { entry: CachedJwks; getKey: ReturnType<typeof createLocalJWKSet> }>();
const lastAttempt = new Map<string, number>();
const MAX_AGE_MS = 10 * 60_000;
const COOLDOWN_MS = 30_000;

/** Forget keys held in memory (a test, or to force a refetch). The cache file is kept. */
export function clearJwksMemory() {
  jwksCache.clear();
  lastAttempt.clear();
}

function cacheFile(opts: KeySetOptions): string | undefined {
  return opts.jwksCacheFile ?? (globalThis as { process?: { env?: Record<string, string | undefined> } }).process?.env?.OPENRMS_JWKS_CACHE_FILE;
}

async function readFileCache(file: string, issuer: string): Promise<CachedJwks | undefined> {
  try {
    const { readFile } = await import("node:fs/promises");
    const all = JSON.parse(await readFile(file, "utf8")) as Record<string, CachedJwks>;
    const e = all[issuer];
    return e?.jwks?.keys?.length ? e : undefined;
  } catch {
    return undefined;
  }
}

async function writeFileCache(file: string, issuer: string, entry: CachedJwks) {
  try {
    const { readFile, writeFile, rename } = await import("node:fs/promises");
    let all: Record<string, CachedJwks> = {};
    try { all = JSON.parse(await readFile(file, "utf8")); } catch { /* new file */ }
    all[issuer] = entry;
    const tmp = `${file}.${process.pid}.tmp`;
    await writeFile(tmp, JSON.stringify(all), { mode: 0o644 });
    await rename(tmp, file);
  } catch (e) {
    console.error(`[openrms auth] couldn't write JWKS cache ${file}:`, (e as Error).message);
  }
}

async function fetchJwks(issuer: string): Promise<CachedJwks> {
  const timeout = AbortSignal.timeout(5000);
  const d = await fetch(`${issuer}/.well-known/openid-configuration`, { signal: timeout });
  if (!d.ok) throw new Error(`discovery ${d.status}`);
  const { jwks_uri } = (await d.json()) as { jwks_uri?: string };
  if (!jwks_uri) throw new Error("discovery has no jwks_uri");
  const k = await fetch(jwks_uri, { signal: AbortSignal.timeout(5000) });
  if (!k.ok) throw new Error(`jwks ${k.status}`);
  const jwks = (await k.json()) as JSONWebKeySet;
  if (!Array.isArray(jwks.keys) || !jwks.keys.length) throw new Error("jwks has no keys");
  return { jwksUri: jwks_uri, jwks, fetchedAt: Date.now() };
}

function remember(issuer: string, entry: CachedJwks) {
  const v = { entry, getKey: createLocalJWKSet(entry.jwks) };
  jwksCache.set(issuer, v);
  return v;
}

/** Refresh now; on failure keep (and return) what we had. Throws only with nothing to fall back on. */
async function refresh(issuer: string, opts: KeySetOptions) {
  lastAttempt.set(issuer, Date.now());
  try {
    const entry = await fetchJwks(issuer);
    const file = cacheFile(opts);
    if (file) await writeFileCache(file, issuer, entry);
    return remember(issuer, entry);
  } catch (e) {
    const held = jwksCache.get(issuer);
    if (held) {
      console.error(`[openrms auth] JWKS refresh from ${issuer} failed (${(e as Error).message}); using keys fetched ${new Date(held.entry.fetchedAt).toISOString()}`);
      return held;
    }
    throw e;
  }
}

async function current(issuer: string, opts: KeySetOptions) {
  let held = jwksCache.get(issuer);
  if (!held) {
    const file = cacheFile(opts);
    const fromFile = file ? await readFileCache(file, issuer) : undefined;
    if (fromFile) held = remember(issuer, fromFile);
  }
  const maxAge = opts.jwksMaxAgeMs ?? MAX_AGE_MS;
  const stale = !held || Date.now() - held.entry.fetchedAt > maxAge;
  const cooling = Date.now() - (lastAttempt.get(issuer) ?? 0) < (opts.jwksCooldownMs ?? COOLDOWN_MS);
  if (!held || (stale && !cooling)) held = await refresh(issuer, opts);
  return held;
}

/** A jose key resolver that serves cached keys and refetches once for an unknown `kid`. */
function keySet(issuer: string, opts: KeySetOptions): JWTVerifyGetKey {
  return async (header, token) => {
    const held = await current(issuer, opts);
    try {
      return await held.getKey(header, token);
    } catch (e) {
      const code = (e as { code?: string }).code;
      if (code !== "ERR_JWKS_NO_MATCHING_KEY" || Date.now() - (lastAttempt.get(issuer) ?? 0) < (opts.jwksCooldownMs ?? COOLDOWN_MS)) throw e;
      return (await refresh(issuer, opts)).getKey(header, token);
    }
  };
}

interface KeySetOptions {
  jwksCacheFile?: string;
  jwksMaxAgeMs?: number;
  jwksCooldownMs?: number;
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
    const { payload } = await jwtVerify(token, keySet(iss, opts), {
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
  /**
   * Where the pull cursor lives across restarts (optional). The helper advances it itself, only
   * from rows the PULL returned, so a webhook row can never move it past a revocation the pull
   * hasn't seen. Without it the cursor is kept in memory and each start pulls every unexpired
   * revocation for your audience (a bounded list), which is also correct.
   */
  cursor?: { load: () => Promise<string | null>; save: (iso: string) => Promise<void> };
  /**
   * @deprecated Use `cursor`. If given (and `cursor` isn't), read once at start as the initial
   * cursor. It must be max(revoked_at) over PULLED rows only, never over webhook rows.
   */
  lastSync?: () => Promise<string | null>;
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
  private cursorAt: string | null | undefined; // undefined: not loaded yet

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
    if (this.cursorAt === undefined) {
      this.cursorAt = (await (this.opts.cursor?.load() ?? this.opts.lastSync?.())) ?? null;
    }
    const last = this.cursorAt;
    const since = last ? new Date(new Date(last).getTime() - 5 * 60_000).toISOString() : "1970-01-01T00:00:00.000Z";
    const res = await fetch(`${this.issuer}/api/v1/keys/revoked?since=${encodeURIComponent(since)}`, {
      headers: { authorization: `Bearer ${await this.accessToken()}` },
    });
    if (res.status === 401) this.token = undefined;
    if (!res.ok) throw new Error(`GET /api/v1/keys/revoked: HTTP ${res.status}`);
    const body = (await res.json()) as { revoked: RevokedKey[] };
    if (body.revoked.length) {
      await this.opts.store(body.revoked);
      // Advance only after the rows are stored, and only from pulled rows.
      const newest = body.revoked.reduce((m, k) => (k.revoked_at > m ? k.revoked_at : m), last ?? "");
      if (newest && newest !== last) {
        this.cursorAt = newest;
        await this.opts.cursor?.save(newest);
      }
    }
    return body.revoked.length;
  }

  /** Handle a verified webhook event. Returns true for `key.revoked` (stored), false for others. Never moves the pull cursor. */
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
