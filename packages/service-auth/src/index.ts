// @openrms/service-auth: what an openRMS service needs to trust openRMS-Accounts.
// Contract: openRMS-Spec/accounts/identity.md (§3 tokens, §4 claims, §5 keys, §7 webhooks).
import { createHash, createHmac, timingSafeEqual } from "node:crypto";
import { createRemoteJWKSet, jwtVerify, type JWTPayload } from "jose";

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
  /** This service's audience, e.g. "https://directory.openrms.dev". */
  audience: string;
  /** Trusted issuers. Default: OPENRMS_ISSUER (comma-separated). None configured: every token is refused. */
  issuers?: string[];
  /** Allowed clock skew in seconds (default 30). */
  clockTolerance?: number;
}

export class TokenError extends Error {
  constructor(message: string, readonly code: "missing" | "invalid" | "expired" | "untrusted_issuer" | "wrong_audience") {
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
 */
export async function verifyAccessToken(token: string | null | undefined, opts: VerifyOptions): Promise<AccessClaims> {
  if (!token) throw new TokenError("no token", "missing");
  const issuers = (opts.issuers ?? defaultIssuers()).map(trim);
  const iss = decodeIss(token);
  if (!iss) throw new TokenError("not a JWT", "invalid");
  if (!issuers.includes(iss)) throw new TokenError(`issuer ${iss} is not trusted`, "untrusted_issuer");
  try {
    const { payload } = await jwtVerify(token, await keySet(iss), {
      issuer: [iss, `${iss}/`],
      audience: opts.audience,
      clockTolerance: opts.clockTolerance ?? 30,
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
