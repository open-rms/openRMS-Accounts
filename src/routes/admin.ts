// Staff tools for accounts and clubs (moved from openRMS-Atlas (then the Directory)). Every route needs a staff
// role and the permission from src/rbac.ts; actions go to Accounts' audit_log.
import { Hono } from "hono";
import { createMiddleware } from "hono/factory";
import { auth } from "../auth.js";
import { q } from "../db/pool.js";
import { emit } from "../events.js";
import { can, canAssign, outranks, permissionsOf, roleOf, ROLE_NAMES, type RoleName } from "../rbac.js";

type Vars = { Variables: { role: string; userId: string } };
export const adminRoutes = new Hono<Vars>();

adminRoutes.use("*", async (c, next) => {
  const s = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!s) return c.json({ error: "sign in required" }, 401);
  const role = (s.user as { role?: string }).role ?? "user";
  if (roleOf(role) === "user") return c.json({ error: "staff only" }, 403);
  c.set("role", role);
  c.set("userId", s.user.id);
  await next();
});

export async function audit(actor: string | null, action: string, target: string, detail?: unknown) {
  await q(`INSERT INTO audit_log (actor_sub, action, target, detail) VALUES ($1, $2, $3, $4)`, [
    actor, action, target, detail === undefined ? null : JSON.stringify(detail),
  ]);
}

const need = (perms: Parameters<typeof can>[1]) =>
  createMiddleware<Vars>(async (c, next) => {
    if (!can(c.get("role"), perms)) return c.json({ error: "your role doesn't allow this" }, 403);
    await next();
  });

adminRoutes.get("/me", (c) => c.json({ role: roleOf(c.get("role")), permissions: permissionsOf(c.get("role")) }));

/** Assign a staff role, limited by rank (see rbac.ts). */
adminRoutes.post("/users/:id/role", async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as { role?: string };
  const role = body.role as RoleName;
  if (!ROLE_NAMES.includes(role)) return c.json({ error: `role must be one of ${ROLE_NAMES.join(", ")}` }, 400);
  const target = c.req.param("id");
  if (target === c.get("userId")) return c.json({ error: "you can't change your own role" }, 403);
  const { rows } = await q<{ role: string | null }>(`SELECT role FROM "user" WHERE id = $1`, [target]);
  if (!rows[0]) return c.json({ error: "not found" }, 404);
  if (!outranks(c.get("role"), rows[0].role)) return c.json({ error: `you can't change a ${roleOf(rows[0].role)}'s role` }, 403);
  if (!canAssign(c.get("role"), role)) return c.json({ error: `you can't assign ${role}` }, 403);
  await q(`UPDATE "user" SET role = $2, "updatedAt" = now() WHERE id = $1`, [target, role]);
  await audit(c.get("userId"), "role.set", target, { from: roleOf(rows[0].role), to: role });
  await emit("user.updated", { sub: target });
  return c.json({ ok: true });
});

adminRoutes.get("/audit", need({ audit: ["view"] }), async (c) => {
  const { rows } = await q(
    `SELECT a.*, u.callsign AS actor_callsign FROM audit_log a LEFT JOIN "user" u ON u.id = a.actor_sub ORDER BY a.id DESC LIMIT 200`,
  );
  return c.json({ entries: rows });
});

adminRoutes.get("/users", need({ user: ["list"] }), async (c) => {
  const search = (c.req.query("q") ?? "").trim();
  const { rows } = await q(
    `SELECT id, name, email, callsign, "callsignVerified", "callsignVerifiedMethod", role, banned, "createdAt" FROM "user"
      WHERE $1 = '' OR callsign ILIKE $1 || '%' OR email ILIKE '%' || $1 || '%' OR name ILIKE '%' || $1 || '%'
      ORDER BY "createdAt" DESC LIMIT 200`,
    [search],
  );
  return c.json({ users: rows });
});

adminRoutes.post("/users/:id/verify-callsign", need({ callsign: ["verify"] }), async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as { verified?: boolean; method?: string };
  const verified = body.verified ?? true;
  const method = verified ? String(body.method ?? "moderator").slice(0, 64) : null;
  const { rowCount } = await q(`UPDATE "user" SET "callsignVerified" = $2, "callsignVerifiedMethod" = $3, "updatedAt" = now() WHERE id = $1`, [c.req.param("id"), verified, method]);
  if (!rowCount) return c.json({ error: "not found" }, 404);
  await audit(c.get("userId"), "callsign.verify", c.req.param("id"), { verified, method });
  await emit("user.callsign_verified", { sub: c.req.param("id"), verified, method });
  return c.json({ ok: true });
});

adminRoutes.get("/clubs", need({ club: ["list"] }), async (c) => {
  const { rows } = await q(
    `SELECT o.id, o.name, o.callsign, o."callsignVerified", o."callsignVerifiedMethod", o."createdAt",
            (SELECT string_agg(u.callsign || ':' || m.role, ', ') FROM member m JOIN "user" u ON u.id = m."userId" WHERE m."organizationId" = o.id) AS members
       FROM organization o ORDER BY o."createdAt" DESC LIMIT 500`,
  );
  return c.json({ clubs: rows });
});

adminRoutes.post("/clubs/:id/verify-callsign", need({ club: ["verify"] }), async (c) => {
  const body = (await c.req.json().catch(() => ({}))) as { verified?: boolean; method?: string };
  const verified = body.verified ?? true;
  const method = verified ? String(body.method ?? "moderator").slice(0, 64) : null;
  const { rowCount } = await q(`UPDATE organization SET "callsignVerified" = $2, "callsignVerifiedMethod" = $3 WHERE id = $1`, [c.req.param("id"), verified, method]);
  if (!rowCount) return c.json({ error: "not found" }, 404);
  await audit(c.get("userId"), "club.verify", c.req.param("id"), { verified, method });
  await emit("club.verified", { id: c.req.param("id"), verified, method });
  return c.json({ ok: true });
});
