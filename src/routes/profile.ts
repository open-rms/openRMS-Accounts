// Profiles (spec §4a, §6a): the owner's profile settings (cookie) and the public profile by
// callsign or sub, which returns only what the caller may see.
import { Hono, type Context } from "hono";
import { getConnInfo } from "@hono/node-server/conninfo";
import { createLocalJWKSet, decodeProtectedHeader, jwtVerify } from "jose";
import { auth } from "../auth.js";
import { q } from "../db/pool.js";
import { env } from "../env.js";
import { emit } from "../events.js";
import { normalizeCallsign } from "../lib/callsign.js";
import { canSee, DEFAULT_VISIBILITY, FIELDS, gridFor, loadProfile, profileInput, type Viewer } from "../profile.js";
import { requireSession, type SessionVars } from "./session.js";

// ---------------------------------------------------------------- owner: /api/v1/me/profile

export const meProfileRoutes = new Hono<SessionVars>();
meProfileRoutes.use("*", requireSession);

meProfileRoutes.get("/", async (c) => {
  const p = await loadProfile(c.get("session").user.id);
  return c.json({ ...p, defaults: DEFAULT_VISIBILITY, fields: FIELDS });
});

meProfileRoutes.put("/", async (c) => {
  const parsed = profileInput.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return c.json({ error: parsed.error.issues[0]?.message ?? "bad request" }, 400);
  const sub = c.get("session").user.id;
  const cur = await loadProfile(sub);
  const d = parsed.data;
  const clean = (s: string | null | undefined, old: string | null) => (s === undefined ? old : s?.trim() ? s.trim() : null);
  const next = {
    bio: clean(d.bio, cur.bio),
    city: clean(d.city, cur.city),
    links: d.links ?? cur.links,
    visibility: { ...cur.visibility, ...(d.visibility ?? {}) },
    hidden: d.hidden ?? cur.hidden,
  };
  await q(
    `INSERT INTO profile (sub, bio, city, links, visibility, hidden, updated_at) VALUES ($1, $2, $3, $4, $5, $6, now())
     ON CONFLICT (sub) DO UPDATE SET bio = $2, city = $3, links = $4, visibility = $5, hidden = $6, updated_at = now()`,
    [sub, next.bio, next.city, JSON.stringify(next.links), JSON.stringify(next.visibility), next.hidden],
  );
  // Services cache visibility (spec §6) and must hear about it: bumps the account and notifies.
  await emit("user.updated", { sub });
  return c.json(next);
});

// ---------------------------------------------------------------- public: /api/v1/profiles/{callsign|sub}

export const profileRoutes = new Hono();

// Public data: any site may read it. Trusted openRMS origins may send credentials (the session
// adds members-only fields), so they get their origin echoed instead of "*".
profileRoutes.use("*", async (c, next) => {
  const origin = c.req.header("origin");
  const trusted = !!origin && (env.trustedOrigins.includes(origin) || origin === env.ISSUER);
  if (c.req.method === "OPTIONS") {
    return c.body(null, 204, {
      "access-control-allow-origin": trusted ? origin! : "*",
      ...(trusted ? { "access-control-allow-credentials": "true", vary: "Origin" } : {}),
      "access-control-allow-methods": "GET",
      "access-control-allow-headers": "authorization",
      "access-control-max-age": "600",
    });
  }
  await next();
  c.header("access-control-allow-origin", trusted ? origin! : "*");
  if (trusted) {
    c.header("access-control-allow-credentials", "true");
    c.header("vary", "Origin");
  }
});

// 120 lookups a minute per client IP: enough for pages, not for scraping every callsign.
const hits = new Map<string, { n: number; reset: number }>();
function clientIp(c: Context): string {
  for (const h of env.ipHeaders) {
    const v = c.req.header(h);
    if (v) return v.split(",")[0]!.trim();
  }
  try {
    return getConnInfo(c).remote.address ?? "unknown";
  } catch {
    return "unknown";
  }
}
function limited(ip: string): boolean {
  const now = Date.now();
  const h = hits.get(ip);
  if (!h || h.reset < now) {
    hits.set(ip, { n: 1, reset: now + 60_000 });
    if (hits.size > 50_000) for (const [k, v] of hits) if (v.reset < now) hits.delete(k);
    return false;
  }
  return ++h.n > 120;
}

/** A first-party access token (no client_id) for any first-party audience means "signed in". */
async function bearerViewer(header: string | undefined): Promise<string | null> {
  const m = /^Bearer\s+(.+)$/i.exec(header ?? "");
  if (!m) return null;
  try {
    const token = m[1]!.trim();
    if (token.startsWith("ormk_") || decodeProtectedHeader(token).typ === "openrms-key+jwt") return null;
    const jwks = createLocalJWKSet((await auth.api.getJwks()) as never);
    const { payload } = await jwtVerify(token, jwks, { issuer: [env.ISSUER, `${env.ISSUER}/`], audience: [...env.firstPartyAudiences, env.ISSUER] });
    if (payload.client_id || typeof payload.sub !== "string") return null;
    return payload.sub;
  } catch {
    return null;
  }
}

profileRoutes.get("/:id", async (c) => {
  if (limited(clientIp(c))) return c.json({ error: "too many requests" }, 429);
  const id = c.req.param("id");
  const { rows } = await q<{ id: string; name: string; callsign: string; callsignVerified: boolean | null; gridsquare: string | null; banned: boolean | null }>(
    `SELECT id, name, callsign, "callsignVerified", gridsquare, banned FROM "user" WHERE callsign = $1 OR id = $2 LIMIT 1`,
    [normalizeCallsign(id), id],
  );
  const u = rows[0];
  const notFound = () => c.json({ error: "not found" }, 404);
  if (!u || u.banned) return notFound();

  const session = await auth.api.getSession({ headers: c.req.raw.headers }).catch(() => null);
  const viewerSub = session?.user.id ?? (await bearerViewer(c.req.header("authorization")));
  let viewer: Viewer = viewerSub === u.id ? "owner" : viewerSub ? "members" : "public";
  // The owner may preview how others see the page.
  const as = c.req.query("as");
  if (viewer === "owner" && (as === "public" || as === "members")) viewer = as;

  const p = await loadProfile(u.id);
  if (p.hidden && viewer !== "owner") return notFound();
  const v = p.visibility;
  const out: Record<string, unknown> = { sub: u.id, callsign: u.callsign, callsign_verified: !!u.callsignVerified };
  if (canSee(v.name, viewer)) out.name = u.name;
  const grid = gridFor(u.gridsquare, v.grid, viewer);
  if (grid) out.grid = grid;
  if (p.city && canSee(v.city, viewer)) out.city = p.city;
  if (p.bio && canSee(v.bio, viewer)) out.bio = p.bio;
  if (p.links.length && canSee(v.links, viewer)) out.links = p.links;
  if (viewer === "owner") Object.assign(out, { self: true, visibility: v, hidden: p.hidden });
  c.header("Cache-Control", viewer === "public" ? "public, max-age=60" : "private, no-store");
  c.header("Vary", "Origin, Cookie, Authorization");
  return c.json(out);
});
