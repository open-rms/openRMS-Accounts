// Accounts API for services (spec §6). Callers use a client-credentials access token for
// resource = the issuer, from a confidential client registered with metadata.service = true.
import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { bearerToken, verifyAccessToken } from "@openrms/service-auth";
import { clubsOf, loadUser, strongestClubRole } from "../claims.js";
import { q } from "../db/pool.js";
import { env } from "../env.js";
import { normalizeCallsign } from "../lib/callsign.js";
import { effectiveRole } from "../staff.js";
import { loadProfile } from "../profile.js";

type Vars = { Variables: { clientId: string } };
export const serviceRoutes = new Hono<Vars>();

const serviceClients = new Map<string, { ok: boolean; at: number }>();

async function isServiceClient(clientId: string): Promise<boolean> {
  const hit = serviceClients.get(clientId);
  if (hit && Date.now() - hit.at < 60_000) return hit.ok;
  const { rows } = await q<{ metadata: string | null; disabled: boolean | null }>(`SELECT metadata, disabled FROM "oauthClient" WHERE "clientId" = $1`, [clientId]);
  let ok = false;
  try {
    const m = rows[0]?.metadata ? (typeof rows[0].metadata === "string" ? JSON.parse(rows[0].metadata) : rows[0].metadata) : null;
    ok = !!m?.service && !rows[0]?.disabled;
  } catch { /* not a service */ }
  serviceClients.set(clientId, { ok, at: Date.now() });
  return ok;
}

/** Client-credentials callers only, holding `scope` (accounts.read, or accounts.keys for API key routes). */
export const serviceAuth = (scope: "accounts.read" | "accounts.keys") => createMiddleware<Vars>(async (c, next) => {
  try {
    const claims = await verifyAccessToken(bearerToken(c.req.header("authorization")), { audience: env.ISSUER, issuers: [env.ISSUER] });
    // Client credentials: no user, the subject is the client itself.
    if (!claims.client_id || claims.sub !== claims.client_id || !claims.scope.includes(scope) || !(await isServiceClient(claims.client_id))) {
      return c.json({ error: "service clients only" }, 403);
    }
    c.set("clientId", claims.client_id);
  } catch (e) {
    return c.json({ error: (e as Error).message }, 401);
  }
  await next();
});
// Only the service paths: this router is mounted at /api/v1 next to other routes.
// /users/{sub}/keys is an API key route (accounts.keys), mounted from routes/keys.ts first.
const requireService = serviceAuth("accounts.read");
for (const path of ["/users", "/users/*", "/clubs", "/clubs/*"]) {
  serviceRoutes.use(path, async (c, next) => (/^\/api\/v1\/users\/[^/]+\/keys$/.test(c.req.path) ? next() : requireService(c, next)));
}

const publicUser = async (id: string) => {
  const u = await loadUser(id);
  if (!u) return null;
  return {
    sub: u.id, name: u.name, callsign: u.callsign, callsign_verified: !!u.callsignVerified, callsign_verified_method: u.callsignVerifiedMethod,
    grid: u.gridsquare, role: await effectiveRole(u.id, u.role), banned: !!u.banned, clubs: await clubsOf(u.id),
    // Full values above are for server-side use; show other people only what this allows (spec §4a).
    visibility: await (async () => { const p = await loadProfile(u.id); return { ...p.visibility, hidden: p.hidden }; })(),
  };
};

serviceRoutes.get("/users/:sub", async (c) => {
  const u = await publicUser(c.req.param("sub"));
  return u ? c.json(u) : c.json({ error: "not found" }, 404);
});

/** Resolve by callsign (?callsign=W1AW), or list changed accounts for reconcile (?updatedSince=ISO). */
serviceRoutes.get("/users", async (c) => {
  const call = c.req.query("callsign");
  if (call) {
    const { rows } = await q<{ id: string }>(`SELECT id FROM "user" WHERE callsign = $1`, [normalizeCallsign(call)]);
    return c.json({ users: rows[0] ? [await publicUser(rows[0].id)] : [] });
  }
  const since = c.req.query("updatedSince");
  const { rows } = await q<{ id: string }>(
    `SELECT id FROM "user" WHERE $1::timestamptz IS NULL OR "updatedAt" >= $1::timestamptz ORDER BY "updatedAt" LIMIT 1000`,
    [since ?? null],
  );
  return c.json({ users: await Promise.all(rows.map((r) => publicUser(r.id))) });
});

/** Every club that exists (ids, callsigns, verification): lets a service drop deleted clubs on reconcile. */
serviceRoutes.get("/clubs", async (c) => {
  const { rows } = await q(
    `SELECT id, name, callsign, COALESCE("callsignVerified", false) AS verified, "callsignVerifiedMethod" AS verified_method FROM organization ORDER BY callsign`,
  );
  return c.json({ clubs: rows });
});

serviceRoutes.get("/clubs/:id", async (c) => {
  const { rows } = await q(
    `SELECT id, name, callsign, COALESCE("callsignVerified", false) AS verified, "callsignVerifiedMethod" AS verified_method FROM organization WHERE id = $1`,
    [c.req.param("id")],
  );
  return rows[0] ? c.json(rows[0]) : c.json({ error: "not found" }, 404);
});

serviceRoutes.get("/clubs/:id/members", async (c) => {
  const { rows } = await q<{ sub: string; callsign: string; role: string }>(
    `SELECT m."userId" AS sub, u.callsign, m.role FROM member m JOIN "user" u ON u.id = m."userId" WHERE m."organizationId" = $1 ORDER BY u.callsign`,
    [c.req.param("id")],
  );
  return c.json({ members: rows.map((r) => ({ ...r, role: strongestClubRole(r.role) })) });
});
