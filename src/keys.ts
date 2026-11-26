// API keys (openRMS-Spec/accounts/identity.md §5). Accounts mints every key as `ormk_` + a JWT
// signed with the issuer's JWKS; services verify offline and keep a persisted denylist fed by
// `key.revoked` and GET /api/v1/keys/revoked. This module: the service and scope registry,
// minting, renewal, revocation and expiry reminders.
import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify, type JWTPayload } from "jose";
import { signJWT } from "better-auth/plugins/jwt";
import { auth, JWT_OPTIONS } from "./auth.js";
import { pool, q, tx } from "./db/pool.js";
import { env } from "./env.js";
import { emit } from "./events.js";
import { sendMail } from "./lib/mail.js";

export const KEY_PREFIX = "ormk_";
export const KEY_TYP = "openrms-key+jwt";
export const MAX_DAYS = 365;
export const DEFAULT_DAYS = 90;
export const MAX_ACTIVE = 50;
/** A lost renewal response may be retried with the old key for this long (spec §5.4). */
const RETRY_WINDOW_MS = 10 * 60_000;

export class KeyError extends Error {
  constructor(message: string, readonly status: 400 | 401 | 403 | 404 | 409 = 400) {
    super(message);
  }
}

// ---------------------------------------------------------------- services and scopes (§5.2)

export interface ScopeInfo { scope: string; description: string }
export interface KeyService { aud: string; name: string; scopes: ScopeInfo[]; source: "metadata" | "built-in" }

// Used until a service publishes RFC 9728 metadata (and never again once one copy was read).
// Same lists as the spec's §5.2 table.
const BUILT_IN: { match: RegExp; name: string; clientId: string; scopes: ScopeInfo[] }[] = [
  {
    match: /\/\/atlas\.|:8787$/, name: "Atlas", clientId: "openrms-atlas",
    scopes: [
      { scope: "heartbeat", description: "Send gateway heartbeats and still-on-air confirmations" },
      { scope: "watch:ingest", description: "Upload watcher reports" },
      { scope: "gateways:read", description: "List your own gateways" },
      { scope: "gateways:write", description: "Add and edit your own gateways" },
    ],
  },
  {
    match: /\/\/rigs\.|:8790$/, name: "Rigs", clientId: "openrms-rigs",
    scopes: [
      { scope: "profiles:write", description: "Submit and edit your own rig profiles" },
      { scope: "profiles:read-private", description: "Read your own pending or hidden profiles" },
      { scope: "favorites", description: "Read and change your favorites" },
      { scope: "reports:write", description: "Report that a profile worked for you" },
      { scope: "comments:write", description: "Post comments" },
    ],
  },
];

/** Which audience a service client may see in the keys service API (spec §6). */
export function audienceOfClient(clientId: string): string | null {
  const b = BUILT_IN.find((x) => x.clientId === clientId);
  return (b && env.resources.find((r) => b.match.test(r))) ?? null;
}

const metaCache = new Map<string, { at: number; svc: KeyService }>();
const META_TTL = 60 * 60_000;

async function fetchMetadata(aud: string): Promise<KeyService | null> {
  const res = await fetch(`${aud}/.well-known/oauth-protected-resource`, { signal: AbortSignal.timeout(3000) });
  if (!res.ok) return null;
  const m = (await res.json()) as { resource?: string; resource_name?: string; openrms_key_scopes?: ScopeInfo[] };
  if (m.resource && m.resource.replace(/\/+$/, "") !== aud) return null;
  if (!Array.isArray(m.openrms_key_scopes)) return null;
  const scopes = m.openrms_key_scopes
    .filter((s) => typeof s?.scope === "string" && /^[a-z][a-z0-9:._-]{0,63}$/.test(s.scope))
    .map((s) => ({ scope: s.scope, description: String(s.description ?? "").slice(0, 200) }));
  return { aud, name: m.resource_name?.slice(0, 60) || builtIn(aud)?.name || aud, scopes, source: "metadata" };
}

const builtIn = (aud: string) => BUILT_IN.find((b) => b.match.test(aud));

/** Every service a key can be for, with its key-grantable scopes. */
export async function keyServices(): Promise<KeyService[]> {
  const auds = env.resources.filter((r) => r !== env.ISSUER);
  return (await Promise.all(auds.map(serviceFor))).filter((s): s is KeyService => !!s);
}

export async function serviceFor(aud: string): Promise<KeyService | null> {
  if (!env.resources.includes(aud) || aud === env.ISSUER) return null;
  const hit = metaCache.get(aud);
  if (hit && Date.now() - hit.at < META_TTL) return hit.svc;
  try {
    const svc = await fetchMetadata(aud);
    if (svc) {
      metaCache.set(aud, { at: Date.now(), svc });
      return svc;
    }
  } catch { /* unreachable: fall back below */ }
  if (hit) return hit.svc; // last good copy
  const b = builtIn(aud);
  return b ? { aud, name: b.name, scopes: b.scopes, source: "built-in" } : null;
}

// ---------------------------------------------------------------- client key policies (§5.3)

interface KeyPolicy { match: RegExp; scopes: string[]; renewable: boolean; maxDays: number }
/** What each device client may mint with a `keys` token. */
export const KEY_POLICIES: Record<string, KeyPolicy> = {
  "openrms-watch": { match: /\/\/atlas\.|:8787$/, scopes: ["watch:ingest"], renewable: true, maxDays: 365 },
};

// ---------------------------------------------------------------- minting

export interface KeyRow {
  jti: string; sub: string; aud: string; scopes: string[]; name: string; created_at: Date; expires_at: Date; days: number;
  renewable: boolean; client_id: string | null; replaces: string | null; replaced_by: string | null;
  last_used_at: Date | null; revoked_at: Date | null; revoke_reason: string | null;
}

export interface MintInput {
  sub: string;
  aud: string;
  scopes: string[];
  name: string;
  days?: number;
  renewable?: boolean;
  clientId?: string | null;
  replaces?: string;
}

async function sign(payload: JWTPayload): Promise<string> {
  const ctx = await auth.$context;
  return signJWT({ context: ctx } as never, { options: JWT_OPTIONS, payload: payload as never, header: { typ: KEY_TYP } } as never);
}

/** Mint a key; the caller has checked who may ask. Returns the key (shown once) and its row. */
export async function mintKey(input: MintInput, client?: PoolClient): Promise<{ key: string; row: KeyRow }> {
  const svc = await serviceFor(input.aud);
  if (!svc) throw new KeyError(`unknown service ${input.aud}`);
  const scopes = [...new Set(input.scopes)];
  if (!scopes.length) throw new KeyError("pick at least one scope");
  const allowed = new Set(svc.scopes.map((s) => s.scope));
  const bad = scopes.filter((s) => !allowed.has(s));
  if (bad.length) throw new KeyError(`${svc.name} doesn't offer ${bad.join(", ")} for API keys`);
  const days = input.days ?? DEFAULT_DAYS;
  if (!Number.isInteger(days) || days < 1 || days > MAX_DAYS) throw new KeyError(`expiry must be 1 to ${MAX_DAYS} days`);
  const name = input.name.trim().slice(0, 80);
  if (!name) throw new KeyError("name the key");
  const run = client ? client.query.bind(client) : pool.query.bind(pool);
  const { rows: user } = await run(`SELECT callsign, banned FROM "user" WHERE id = $1`, [input.sub]);
  if (!user[0]) throw new KeyError("no such account", 404);
  if (user[0].banned) throw new KeyError("account banned", 403);
  const { rows: active } = await run(`SELECT count(*)::int AS n FROM api_key WHERE sub = $1 AND revoked_at IS NULL AND expires_at > now()`, [input.sub]);
  if (active[0].n >= MAX_ACTIVE && !input.replaces) throw new KeyError(`you have ${MAX_ACTIVE} active keys; revoke some first`, 409);

  const jti = randomUUID();
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + days * 86400;
  const jwt = await sign({
    iss: env.ISSUER, sub: input.sub, aud: input.aud, jti, iat, exp,
    scope: scopes.join(" "), token_use: "api_key", callsign: user[0].callsign,
    ...(input.renewable ? { renewable: true } : {}),
    ...(input.replaces ? { replaces: input.replaces } : {}),
  });
  const { rows } = await run(
    `INSERT INTO api_key (jti, sub, aud, scopes, name, expires_at, days, renewable, client_id, replaces)
     VALUES ($1, $2, $3, $4, $5, to_timestamp($6), $7, $8, $9, $10) RETURNING *`,
    [jti, input.sub, input.aud, scopes, name, exp, days, !!input.renewable, input.clientId ?? null, input.replaces ?? null],
  );
  await run(`INSERT INTO audit_log (actor_sub, action, target, detail) VALUES ($1, 'key.created', $1, $2)`, [
    input.sub, JSON.stringify({ jti, aud: input.aud, scopes, name, days, client: input.clientId ?? null, replaces: input.replaces ?? null }),
  ]);
  return { key: KEY_PREFIX + jwt, row: rows[0] as KeyRow };
}

// ---------------------------------------------------------------- revocation

/** Revoke matching unrevoked keys and tell each key's service. Returns the revoked rows. */
export async function revokeWhere(where: string, params: unknown[], reason: string, client?: PoolClient): Promise<KeyRow[]> {
  const work = async (c: PoolClient) => {
    const { rows } = await c.query<KeyRow>(
      `UPDATE api_key SET revoked_at = now(), revoke_reason = $${params.length + 1} WHERE revoked_at IS NULL AND (${where}) RETURNING *`,
      [...params, reason],
    );
    for (const r of rows) {
      await emit("key.revoked", { jti: r.jti, aud: r.aud, sub: r.sub, exp: Math.floor(r.expires_at.getTime() / 1000) }, c, r.aud);
    }
    return rows;
  };
  return client ? work(client) : tx(work);
}

export const revokeKey = (sub: string, jti: string) => revokeWhere(`sub = $1 AND jti = $2`, [sub, jti], "revoked");
/** Every key of the account, including renewal chains (each link is its own row). */
export const revokeAllKeys = (sub: string, reason = "revoke-all", client?: PoolClient) => revokeWhere(`sub = $1`, [sub], reason, client);

// ---------------------------------------------------------------- verifying our own keys and tokens

async function localJwks() {
  const jwks = (await auth.api.getJwks()) as { keys: never[] };
  return createLocalJWKSet(jwks as never);
}

/** Verify an `ormk_` key Accounts issued (signature, typ, expiry); the row is checked by the caller. */
export async function verifyOwnKey(raw: string): Promise<JWTPayload & { jti: string; sub: string; aud: string }> {
  if (!raw.startsWith(KEY_PREFIX)) throw new KeyError("not an API key", 401);
  const jwt = raw.slice(KEY_PREFIX.length);
  try {
    if (decodeProtectedHeader(jwt).typ !== KEY_TYP) throw new Error("wrong typ");
    const { payload } = await jwtVerify(jwt, await localJwks(), { issuer: env.ISSUER, typ: KEY_TYP });
    if (payload.token_use !== "api_key" || typeof payload.jti !== "string" || typeof payload.sub !== "string") throw new Error("not a key");
    return payload as never;
  } catch (e) {
    throw new KeyError(`invalid API key: ${(e as Error).message}`, 401);
  }
}

/** Verify an access token for Accounts itself (aud = issuer), e.g. a device app's `keys` token. */
export async function verifyOwnAccessToken(raw: string): Promise<JWTPayload & { sub: string; scope: string[]; client_id?: string }> {
  try {
    if (raw.startsWith(KEY_PREFIX) || decodeProtectedHeader(raw).typ === KEY_TYP) throw new Error("API keys can't mint keys");
    const { payload } = await jwtVerify(raw, await localJwks(), { issuer: [env.ISSUER, `${env.ISSUER}/`], audience: env.ISSUER });
    if (typeof payload.sub !== "string") throw new Error("no subject");
    const scope = typeof payload.scope === "string" ? payload.scope.split(" ").filter(Boolean) : [];
    return { ...payload, sub: payload.sub, scope } as never;
  } catch (e) {
    throw new KeyError(`invalid token: ${(e as Error).message}`, 401);
  }
}

// ---------------------------------------------------------------- renewal (§5.4)

/**
 * Renew a renewable key: same sub, aud, scopes, name and lifetime; the old one is revoked and
 * points at the new one. A retry with the old key within the window replaces the previous
 * replacement instead. Emails the owner.
 */
export async function renewKey(raw: string): Promise<{ key: string; row: KeyRow }> {
  const claims = await verifyOwnKey(raw);
  const result = await tx(async (c) => {
    const { rows } = await c.query<KeyRow>(`SELECT * FROM api_key WHERE jti = $1 FOR UPDATE`, [claims.jti]);
    const old = rows[0];
    if (!old) throw new KeyError("unknown API key", 401);
    if (!old.renewable) throw new KeyError("this key can't renew itself", 403);
    if (old.expires_at.getTime() <= Date.now()) throw new KeyError("this key has expired; make a new one", 401);
    if (old.revoked_at) {
      const retry = old.revoke_reason === "renewed" && Date.now() - old.revoked_at.getTime() < RETRY_WINDOW_MS;
      if (!retry) throw new KeyError("this key was revoked", 401);
      if (old.replaced_by) await revokeWhere(`jti = $1`, [old.replaced_by], "renewed", c);
    }
    const fresh = await mintKey(
      { sub: old.sub, aud: old.aud, scopes: old.scopes, name: old.name, days: old.days, renewable: true, clientId: old.client_id, replaces: old.jti },
      c,
    );
    if (!old.revoked_at) await revokeWhere(`jti = $1`, [old.jti], "renewed", c);
    await c.query(`UPDATE api_key SET replaced_by = $2 WHERE jti = $1`, [old.jti, fresh.row.jti]);
    return { ...fresh, old };
  });
  const { rows } = await q<{ email: string; callsign: string }>(`SELECT email, callsign FROM "user" WHERE id = $1`, [result.old.sub]);
  if (rows[0]) {
    await sendMail(
      rows[0].email,
      `openRMS: API key "${result.old.name}" renewed itself`,
      `Your API key "${result.old.name}" for ${result.old.aud} was renewed by the device holding it and now runs until ${result.row.expires_at.toUTCString()}.\n\nIf you don't recognise this, revoke it at ${env.UI_URL}/keys.`,
    ).catch((e) => console.error("[keys] renewal mail failed", (e as Error).message));
  }
  return { key: result.key, row: result.row };
}

// ---------------------------------------------------------------- expiry reminders

/** Email owners 14 and 3 days before a key expires (renewable keys renew themselves: skipped). */
export async function sendExpiryReminders(): Promise<number> {
  let sent = 0;
  for (const days of [14, 3]) {
    const { rows } = await q<KeyRow & { email: string }>(
      `UPDATE api_key k SET reminded_days = $1 FROM "user" u
        WHERE u.id = k.sub AND k.revoked_at IS NULL AND NOT k.renewable
          AND k.expires_at > now() AND k.expires_at <= now() + make_interval(days => $1)
          AND (k.reminded_days IS NULL OR k.reminded_days > $1)
        RETURNING k.*, u.email`,
      [days],
    );
    for (const k of rows) {
      await sendMail(
        k.email,
        `openRMS: API key "${k.name}" expires in ${days} days`,
        `Your API key "${k.name}" for ${k.aud} stops working on ${k.expires_at.toUTCString()}.\nMake a new one at ${env.UI_URL}/keys and put it where the old one is used.`,
      ).catch((e) => console.error("[keys] reminder mail failed", (e as Error).message));
      sent++;
    }
  }
  return sent;
}

export function startKeyReminders(intervalMs = 60 * 60_000) {
  const run = () => sendExpiryReminders().catch((e) => console.error("[keys] reminders failed", e));
  setTimeout(run, 30_000).unref();
  setInterval(run, intervalMs).unref();
}

/** API shape of a key in lists (never the key itself). */
export function publicKey(r: KeyRow) {
  return {
    jti: r.jti, aud: r.aud, scopes: r.scopes, name: r.name, created_at: r.created_at, expires_at: r.expires_at,
    last_used_at: r.last_used_at, revoked_at: r.revoked_at, revoke_reason: r.revoke_reason,
    renewable: r.renewable, client_id: r.client_id, replaces: r.replaces, replaced_by: r.replaced_by,
  };
}
