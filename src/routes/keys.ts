// API keys (spec §5): the owner's page API (cookie), device minting and renewal (bearer), and the
// endpoints services call with client credentials (scope accounts.keys).
import { Hono } from "hono";
import { z } from "zod";
import { bearerToken } from "@openrms/service-auth";
import { q } from "../db/pool.js";
import { env } from "../env.js";
import {
  audienceOfClient, KEY_POLICIES, KeyError, keyServices, mintKey, publicKey, renewKey, revokeAllKeys, revokeKey,
  verifyOwnAccessToken, type KeyRow, DEFAULT_DAYS, MAX_DAYS,
} from "../keys.js";
import { serviceAuth } from "./service.js";
import { requireSession, type SessionVars } from "./session.js";

const fail = (e: unknown) => {
  if (e instanceof KeyError) return { body: { error: e.message }, status: e.status };
  throw e;
};

const mintBody = z.object({
  aud: z.string().url().transform((s) => s.replace(/\/+$/, "")),
  scopes: z.array(z.string()).min(1).max(20),
  name: z.string().min(1).max(80),
  days: z.number().int().min(1).max(MAX_DAYS).default(DEFAULT_DAYS),
});

// ---------------------------------------------------------------- owner (cookie): /api/v1/me/keys

export const meKeyRoutes = new Hono<SessionVars>();
meKeyRoutes.use("*", requireSession);

/** Minting needs a session that signed in within 24 h (spec §5.3). */
const FRESH_MS = 24 * 3600_000;

meKeyRoutes.get("/", async (c) => {
  const s = c.get("session");
  // Live keys, plus revoked or expired ones for 30 days so a renewal chain stays readable.
  const { rows } = await q<KeyRow>(
    `SELECT * FROM api_key WHERE sub = $1 AND (revoked_at IS NULL OR revoked_at > now() - interval '30 days') AND expires_at > now() - interval '30 days'
      ORDER BY created_at DESC`,
    [s.user.id],
  );
  const fresh = Date.now() - new Date(s.session.createdAt).getTime() < FRESH_MS;
  return c.json({ keys: rows.map(publicKey), services: await keyServices(), canCreate: fresh, defaultDays: DEFAULT_DAYS, maxDays: MAX_DAYS });
});

meKeyRoutes.post("/", async (c) => {
  const s = c.get("session");
  if (Date.now() - new Date(s.session.createdAt).getTime() >= FRESH_MS) {
    return c.json({ error: "sign in again to make a key (your sign-in is more than a day old)", reauth: true }, 403);
  }
  const body = mintBody.safeParse(await c.req.json().catch(() => ({})));
  if (!body.success) return c.json({ error: body.error.issues[0]?.message ?? "bad request" }, 400);
  try {
    const { key, row } = await mintKey({ sub: s.user.id, ...body.data });
    c.header("Cache-Control", "no-store");
    return c.json({ key, ...publicKey(row) }, 201);
  } catch (e) {
    const f = fail(e);
    return c.json(f.body, f.status);
  }
});

meKeyRoutes.post("/revoke-all", async (c) => {
  const revoked = await revokeAllKeys(c.get("session").user.id);
  return c.json({ revoked: revoked.length });
});

meKeyRoutes.delete("/:jti", async (c) => {
  const revoked = await revokeKey(c.get("session").user.id, c.req.param("jti"));
  return revoked.length ? c.body(null, 204) : c.json({ error: "no such live key" }, 404);
});

// ---------------------------------------------------------------- devices and services: /api/v1/keys

export const keyRoutes = new Hono<{ Variables: { clientId: string } }>();

/** A device app mints a key with its `keys` access token, within its client's key policy. */
keyRoutes.post("/", async (c) => {
  try {
    const token = bearerToken(c.req.header("authorization"));
    if (!token) return c.json({ error: "Authorization: Bearer <access token> required" }, 401);
    const claims = await verifyOwnAccessToken(token);
    if (!claims.scope.includes("keys")) return c.json({ error: "the token needs the keys scope" }, 403);
    const policy = claims.client_id ? KEY_POLICIES[claims.client_id] : undefined;
    if (!policy) return c.json({ error: "this app may not make API keys" }, 403);
    const raw = (await c.req.json().catch(() => ({}))) as Record<string, unknown>;
    const body = mintBody.safeParse({ ...raw, days: raw.expires_in_days ?? raw.days });
    if (!body.success) return c.json({ error: body.error.issues[0]?.message ?? "bad request" }, 400);
    const { aud, scopes, name, days } = body.data;
    if (!policy.match.test(aud)) return c.json({ error: `this app may not make keys for ${aud}` }, 403);
    const extra = scopes.filter((s) => !policy.scopes.includes(s));
    if (extra.length) return c.json({ error: `this app may not grant ${extra.join(", ")}` }, 403);
    if (days > policy.maxDays) return c.json({ error: `at most ${policy.maxDays} days for this app` }, 400);
    const { key, row } = await mintKey({ sub: claims.sub, aud, scopes, name, days, renewable: policy.renewable, clientId: claims.client_id });
    c.header("Cache-Control", "no-store");
    return c.json({ key, ...publicKey(row) }, 201);
  } catch (e) {
    const f = fail(e);
    return c.json(f.body, f.status);
  }
});

/** A renewable key replaces itself (spec §5.4). */
keyRoutes.post("/renew", async (c) => {
  try {
    const token = bearerToken(c.req.header("authorization"));
    if (!token) return c.json({ error: "Authorization: Bearer ormk_… required" }, 401);
    const { key, row } = await renewKey(token);
    c.header("Cache-Control", "no-store");
    return c.json({ key, ...publicKey(row) }, 201);
  } catch (e) {
    const f = fail(e);
    return c.json(f.body, f.status);
  }
});

const keysService = serviceAuth("accounts.keys");

/** Revocations for the caller's audience that haven't expired yet (spec §6). */
keyRoutes.get("/revoked", keysService, async (c) => {
  const aud = audienceOfClient(c.get("clientId"));
  if (!aud) return c.json({ error: "no audience for this client" }, 403);
  const since = new Date(c.req.query("since") ?? 0);
  if (Number.isNaN(since.getTime())) return c.json({ error: "since must be an ISO date" }, 400);
  const { rows } = await q<{ jti: string; sub: string; exp: number; revoked_at: Date }>(
    `SELECT jti, sub, extract(epoch FROM expires_at)::bigint AS exp, revoked_at FROM api_key
      WHERE aud = $1 AND revoked_at IS NOT NULL AND revoked_at >= $2 AND expires_at > now() ORDER BY revoked_at LIMIT 10000`,
    [aud, since],
  );
  return c.json({ revoked: rows.map((r) => ({ ...r, exp: Number(r.exp), revoked_at: r.revoked_at.toISOString() })) });
});

/** Services report use in batches; recorded to the minute, only for their own keys. */
keyRoutes.post("/used", keysService, async (c) => {
  const aud = audienceOfClient(c.get("clientId"));
  if (!aud) return c.json({ error: "no audience for this client" }, 403);
  const body = z.array(z.object({ jti: z.string().max(64), at: z.string() })).max(5000).safeParse(await c.req.json().catch(() => null));
  if (!body.success) return c.json({ error: "expected [{jti, at}]" }, 400);
  const now = Date.now();
  const items = body.data
    .map((u) => ({ jti: u.jti, at: new Date(u.at) }))
    .filter((u) => !Number.isNaN(u.at.getTime()) && u.at.getTime() <= now + 60_000);
  if (items.length) {
    await q(
      `UPDATE api_key k SET last_used_at = date_trunc('minute', u.at)
         FROM unnest($2::text[], $3::timestamptz[]) AS u(jti, at)
        WHERE k.jti = u.jti AND k.aud = $1 AND (k.last_used_at IS NULL OR k.last_used_at < date_trunc('minute', u.at))`,
      [aud, items.map((i) => i.jti), items.map((i) => i.at.toISOString())],
    );
  }
  return c.json({ ok: true, recorded: items.length });
});

// ---------------------------------------------------------------- services: /api/v1/users/{sub}/keys

export const userKeyRoutes = new Hono<{ Variables: { clientId: string } }>();
userKeyRoutes.get("/users/:sub/keys", keysService, async (c) => {
  const aud = audienceOfClient(c.get("clientId"));
  if (!aud) return c.json({ error: "no audience for this client" }, 403);
  const { rows } = await q<KeyRow>(
    `SELECT * FROM api_key WHERE sub = $1 AND aud = $2 AND revoked_at IS NULL AND expires_at > now() ORDER BY created_at DESC`,
    [c.req.param("sub"), aud],
  );
  return c.json({ keys: rows.map(publicKey), manage: `${env.UI_URL}/keys` });
});
