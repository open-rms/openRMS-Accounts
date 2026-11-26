// The signed-in account: profile and clubs. Club routes moved from openRMS-Atlas (then the Directory); changes
// that bypass Better Auth's own endpoints emit their events here (spec §7).
import { Hono } from "hono";
import { z } from "zod";
import { auth } from "../auth.js";
import { clubsOf, strongestClubRole } from "../claims.js";
import { q } from "../db/pool.js";
import { emit } from "../events.js";
import { normalizeCallsign } from "../lib/callsign.js";
import { permissionsOf, roleOf } from "../rbac.js";
import { effectiveRole, staffNeedsSecondFactor } from "../staff.js";
import { requireSession, type SessionVars } from "./session.js";
import { pendingDeletion } from "../deletion.js";

export const meRoutes = new Hono<SessionVars>();

type U = { id: string; name: string; email: string; callsign: string; callsignVerified?: boolean | null; callsignVerifiedMethod?: string | null; gridsquare?: string | null; role?: string | null };

meRoutes.get("/", async (c) => {
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session) return c.json({ user: null });
  const u = session.user as typeof session.user & U & { twoFactorEnabled?: boolean | null };
  const role = await effectiveRole(u.id, u.role);
  const { rows: pk } = await q<{ n: number }>(`SELECT count(*)::int AS n FROM passkey WHERE "userId" = $1`, [u.id]);
  return c.json({
    user: {
      id: u.id, name: u.name, email: u.email, emailVerified: u.emailVerified, callsign: u.callsign, callsignVerified: !!u.callsignVerified,
      callsignVerifiedMethod: u.callsignVerifiedMethod ?? null, gridsquare: u.gridsquare ?? null, role,
      twoFactorEnabled: !!u.twoFactorEnabled, passkeys: pk[0]?.n ?? 0,
    },
    permissions: permissionsOf(role),
    /** Holds a staff role it can't use until a second factor is set up (spec §4b). */
    staffNeedsSecondFactor: await staffNeedsSecondFactor(u.id, u.role),
    /** The role held, whether or not it can be used yet. */
    storedRole: roleOf(u.role),
    /** When a self-service deletion will happen, if one is pending (spec §4c). */
    pendingDeletion: await pendingDeletion(u.id),
    clubs: await clubsOf(u.id),
  });
});

// ---------------------------------------------------------------- clubs

meRoutes.use("/clubs/*", requireSession);
meRoutes.use("/clubs", requireSession);

async function myRole(orgId: string, userId: string): Promise<"owner" | "admin" | "member" | null> {
  const { rows } = await q<{ role: string }>(`SELECT role FROM member WHERE "organizationId" = $1 AND "userId" = $2`, [orgId, userId]);
  return rows[0] ? strongestClubRole(rows[0].role) : null;
}

function apiError(e: unknown): { message: string; status: 400 | 403 | 404 } {
  const err = e as { status?: string; body?: { message?: string }; message?: string };
  const status = err.status === "FORBIDDEN" ? 403 : err.status === "NOT_FOUND" ? 404 : 400;
  return { message: err.body?.message ?? err.message ?? "request failed", status };
}

async function ownerCount(orgId: string) {
  const { rows } = await q<{ n: number }>(`SELECT count(*)::int AS n FROM member WHERE "organizationId" = $1 AND role LIKE '%owner%'`, [orgId]);
  return rows[0]?.n ?? 0;
}

meRoutes.get("/clubs", async (c) => {
  const s = c.get("session");
  const { rows: clubs } = await q(
    `SELECT o.id, o.name, o.callsign, COALESCE(o."callsignVerified", false) AS verified, m.role
       FROM member m JOIN organization o ON o.id = m."organizationId" WHERE m."userId" = $1 ORDER BY o.callsign`,
    [s.user.id],
  );
  const { rows: members } = await q(
    `SELECT m."organizationId" AS org, m."userId" AS "userId", m.role, u.callsign, u.name
       FROM member m JOIN "user" u ON u.id = m."userId" WHERE m."organizationId" = ANY($1) ORDER BY u.callsign`,
    [clubs.map((x) => x.id)],
  );
  return c.json({
    clubs: clubs.map((o) => ({
      id: o.id, name: o.name, callsign: o.callsign, verified: o.verified, myRole: strongestClubRole(o.role),
      members: members.filter((m) => m.org === o.id).map((m) => ({ userId: m.userId, callsign: m.callsign, name: m.name, role: strongestClubRole(m.role) })),
    })),
  });
});

const createInput = z.object({ callsign: z.string().trim().min(3).max(10), name: z.string().trim().max(80).default("") });

meRoutes.post("/clubs", async (c) => {
  const parsed = createInput.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return c.json({ error: "callsign is required" }, 400);
  const callsign = normalizeCallsign(parsed.data.callsign);
  try {
    // Format and one-holder-per-callsign are checked in the organization hook.
    const org = await auth.api.createOrganization({
      headers: c.req.raw.headers,
      body: { name: parsed.data.name || callsign, slug: callsign.toLowerCase(), callsign } as never,
    });
    return c.json({ id: (org as { id: string }).id }, 201);
  } catch (e) {
    const { message, status } = apiError(e);
    return c.json({ error: message }, status);
  }
});

const memberInput = z.object({ callsign: z.string().trim().min(3), role: z.enum(["member", "admin"]).default("member") });

meRoutes.post("/clubs/:id/members", async (c) => {
  const s = c.get("session");
  const orgId = c.req.param("id");
  const role = await myRole(orgId, s.user.id);
  if (role !== "owner" && role !== "admin") return c.json({ error: "only the club's owner or admins can add members" }, 403);
  const parsed = memberInput.safeParse(await c.req.json().catch(() => null));
  if (!parsed.success) return c.json({ error: "callsign is required" }, 400);
  const call = normalizeCallsign(parsed.data.callsign);
  const { rows } = await q<{ id: string }>(`SELECT id FROM "user" WHERE callsign = $1`, [call]);
  if (!rows[0]) return c.json({ error: `no openRMS account has callsign ${call}; they need to sign up first` }, 404);
  try {
    // Server-only endpoint (permission checked above); afterAddMember emits club.member_added.
    await auth.api.addMember({ body: { userId: rows[0].id, organizationId: orgId, role: parsed.data.role } });
  } catch (e) {
    const { message, status } = apiError(e);
    return c.json({ error: message }, status);
  }
  return c.json({ ok: true }, 201);
});

meRoutes.delete("/clubs/:id/members/:userId", async (c) => {
  const s = c.get("session");
  const orgId = c.req.param("id");
  const target = c.req.param("userId");
  const role = await myRole(orgId, s.user.id);
  const targetRole = await myRole(orgId, target);
  if (!targetRole) return c.json({ error: "not a member" }, 404);
  const leaving = target === s.user.id;
  if (!leaving && role !== "owner" && !(role === "admin" && targetRole === "member")) return c.json({ error: "you can't remove this member" }, 403);
  if (targetRole === "owner" && (await ownerCount(orgId)) <= 1) {
    return c.json({ error: "the last owner can't leave; make someone else owner or delete the club" }, 400);
  }
  await q(`DELETE FROM member WHERE "organizationId" = $1 AND "userId" = $2`, [orgId, target]);
  await emit("club.member_removed", { id: orgId, sub: target });
  return c.body(null, 204);
});

/** Owners can promote a member to owner (club trustee hand-over) or set admin/member. */
meRoutes.put("/clubs/:id/members/:userId", async (c) => {
  const s = c.get("session");
  const orgId = c.req.param("id");
  if ((await myRole(orgId, s.user.id)) !== "owner") return c.json({ error: "only an owner can change roles" }, 403);
  const body = z.object({ role: z.enum(["member", "admin", "owner"]) }).safeParse(await c.req.json().catch(() => null));
  if (!body.success) return c.json({ error: "role must be member, admin or owner" }, 400);
  const target = c.req.param("userId");
  const current = await myRole(orgId, target);
  if (!current) return c.json({ error: "not a member" }, 404);
  if (current === "owner" && body.data.role !== "owner" && (await ownerCount(orgId)) <= 1) return c.json({ error: "a club needs at least one owner" }, 400);
  await q(`UPDATE member SET role = $3 WHERE "organizationId" = $1 AND "userId" = $2`, [orgId, target, body.data.role]);
  await emit("club.member_added", { id: orgId, sub: target, role: body.data.role });
  return c.json({ ok: true });
});

meRoutes.delete("/clubs/:id", async (c) => {
  const s = c.get("session");
  const orgId = c.req.param("id");
  if ((await myRole(orgId, s.user.id)) !== "owner") return c.json({ error: "only an owner can delete the club" }, 403);
  try {
    // afterDeleteOrganization emits club.deleted; services remove their own club data.
    await auth.api.deleteOrganization({ headers: c.req.raw.headers, body: { organizationId: orgId } });
  } catch (e) {
    const { message, status } = apiError(e);
    return c.json({ error: message }, status);
  }
  return c.body(null, 204);
});
