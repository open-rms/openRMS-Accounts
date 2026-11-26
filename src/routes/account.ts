// The account itself (spec §4c): export everything Accounts holds about you, and delete it
// yourself after a grace period.
import { Hono } from "hono";
import { z } from "zod";
import { auth } from "../auth.js";
import { clubsOf } from "../claims.js";
import { q } from "../db/pool.js";
import { env } from "../env.js";
import { cancelDeletion, GRACE_DAYS, pendingDeletion, scheduleDeletion, soleOwnerOf } from "../deletion.js";
import { publicKey, type KeyRow } from "../keys.js";
import { loadProfile } from "../profile.js";
import { radiosOf } from "../radios.js";
import { roleOf } from "../rbac.js";
import { requireSession, type SessionVars } from "./session.js";

/** Deleting needs a sign-in (password and any second factor) within this long. */
const FRESH_MS = 15 * 60_000;

export const meAccountRoutes = new Hono<SessionVars>();
meAccountRoutes.use("*", requireSession);

meAccountRoutes.get("/export", async (c) => {
  const s = c.get("session");
  const sub = s.user.id;
  const [user, sessions, consents, passkeys, keys, audit] = await Promise.all([
    q(`SELECT id, name, email, "emailVerified", callsign, "callsignVerified", "callsignVerifiedMethod", gridsquare, role, banned, "twoFactorEnabled", "createdAt", "updatedAt" FROM "user" WHERE id = $1`, [sub]),
    q(`SELECT "createdAt", "updatedAt", "expiresAt", "ipAddress", "userAgent" FROM session WHERE "userId" = $1 ORDER BY "createdAt" DESC`, [sub]),
    q(`SELECT "clientId", scopes, resources, "createdAt" FROM "oauthConsent" WHERE "userId" = $1 ORDER BY "createdAt"`, [sub]),
    q(`SELECT name, "deviceType", "backedUp", "createdAt" FROM passkey WHERE "userId" = $1 ORDER BY "createdAt"`, [sub]),
    q<KeyRow>(`SELECT * FROM api_key WHERE sub = $1 ORDER BY created_at`, [sub]),
    q(`SELECT at, action, target, detail, (actor_sub = $1) AS by_you FROM audit_log WHERE target = $1 OR actor_sub = $1 ORDER BY id DESC LIMIT 2000`, [sub]),
  ]);
  const u = user.rows[0];
  const body = {
    exported_at: new Date().toISOString(),
    issuer: env.ISSUER,
    note: "Everything openRMS Accounts holds about your account. Other openRMS services (Atlas, Rigs) hold their own data; export it there.",
    account: { ...u, role: roleOf(u?.role) },
    profile: await loadProfile(sub),
    radios: await radiosOf(sub),
    clubs: await clubsOf(sub),
    sessions: sessions.rows,
    connected_apps: consents.rows,
    passkeys: passkeys.rows,
    api_keys: keys.rows.map(publicKey),
    activity: audit.rows,
    pending_deletion: await pendingDeletion(sub),
  };
  c.header("Content-Disposition", `attachment; filename="openrms-account-${u?.callsign ?? sub}.json"`);
  c.header("Cache-Control", "no-store");
  return c.body(JSON.stringify(body, null, 2), 200, { "content-type": "application/json" });
});

meAccountRoutes.get("/deletion", async (c) => {
  const s = c.get("session");
  return c.json({
    pending: await pendingDeletion(s.user.id),
    graceDays: GRACE_DAYS,
    soleOwnerOf: await soleOwnerOf(s.user.id),
    fresh: Date.now() - new Date(s.session.createdAt).getTime() < FRESH_MS,
    superadmin: roleOf((s.user as { role?: string }).role) === "superadmin",
  });
});

meAccountRoutes.post("/deletion", async (c) => {
  const s = c.get("session");
  const u = s.user as typeof s.user & { callsign: string; role?: string };
  const body = z.object({ password: z.string().min(1), confirm: z.string() }).safeParse(await c.req.json().catch(() => null));
  if (!body.success) return c.json({ error: "give your password and type your callsign to confirm" }, 400);
  if (body.data.confirm.trim().toUpperCase() !== u.callsign) return c.json({ error: `type ${u.callsign} to confirm` }, 400);
  if (Date.now() - new Date(s.session.createdAt).getTime() >= FRESH_MS) {
    return c.json({ error: "sign in again (within the last 15 minutes) to delete your account", reauth: true }, 403);
  }
  if (roleOf(u.role) === "superadmin") return c.json({ error: "a superadmin can't delete their own account; hand the role to someone else first" }, 403);
  const clubs = await soleOwnerOf(u.id);
  if (clubs.length) return c.json({ error: `you're the only owner of ${clubs.join(", ")}: make someone else owner or delete the club first`, clubs }, 409);
  const ctx = await auth.$context;
  const credential = (await ctx.internalAdapter.findAccounts(u.id)).find((a) => a.providerId === "credential" && a.password);
  if (credential && !(await ctx.password.verify({ hash: credential.password!, password: body.data.password }))) {
    return c.json({ error: "wrong password" }, 403);
  }
  const deleteAfter = await scheduleDeletion(u.id);
  return c.json({ deleteAfter }, 202);
});

meAccountRoutes.delete("/deletion", async (c) => {
  const sub = await cancelDeletion({ sub: c.get("session").user.id });
  return sub ? c.body(null, 204) : c.json({ error: "no deletion pending" }, 404);
});

/** The emailed link: cancels without signing in (the token is the proof). */
export const deletionCancelRoutes = new Hono();
deletionCancelRoutes.post("/cancel", async (c) => {
  const body = z.object({ token: z.string().min(20).max(100) }).safeParse(await c.req.json().catch(() => null));
  if (!body.success) return c.json({ error: "bad link" }, 400);
  const sub = await cancelDeletion({ token: body.data.token });
  return sub ? c.json({ cancelled: true }) : c.json({ error: "this link has already been used or the account is gone" }, 404);
});
