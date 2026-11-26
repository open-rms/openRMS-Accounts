// Deleting an account, and the self-service path with a grace period (spec §4c). The same
// deleteAccount() runs for the CLI, for staff and when a scheduled self-deletion comes due.
import { createHash, randomBytes } from "node:crypto";
import { q, tx } from "./db/pool.js";
import { env } from "./env.js";
import { emit } from "./events.js";
import { revokeAllKeys } from "./keys.js";
import { sendMail } from "./lib/mail.js";

export const GRACE_DAYS = 7;

/** Clubs this account is the only owner of (deleting would leave them ownerless). */
export async function soleOwnerOf(sub: string): Promise<string[]> {
  const { rows } = await q<{ callsign: string }>(
    `SELECT o.callsign FROM member m JOIN organization o ON o.id = m."organizationId"
      WHERE m."userId" = $1 AND m.role LIKE '%owner%'
        AND (SELECT count(*) FROM member m2 WHERE m2."organizationId" = o.id AND m2.role LIKE '%owner%') = 1`,
    [sub],
  );
  return rows.map((r) => r.callsign);
}

/**
 * Permanent. Services hear club.member_removed for each club, key.revoked for each live key and
 * user.deleted, in one transaction with the delete. Sessions, logins, tokens, consents,
 * memberships, profile and radios go with the row (FK cascade).
 */
export async function deleteAccount(sub: string, actor: string | null, reason: string): Promise<boolean> {
  const done = await tx(async (c) => {
    const { rows } = await c.query<{ callsign: string }>(`SELECT callsign FROM "user" WHERE id = $1 FOR UPDATE`, [sub]);
    if (!rows[0]) return null;
    const { rows: clubs } = await c.query<{ id: string }>(`SELECT "organizationId" AS id FROM member WHERE "userId" = $1`, [sub]);
    for (const club of clubs) await emit("club.member_removed", { id: club.id, sub }, c);
    await revokeAllKeys(sub, "deleted", c);
    await emit("user.deleted", { sub, callsign: rows[0].callsign }, c);
    await c.query(`DELETE FROM account_deletion WHERE sub = $1`, [sub]);
    await c.query(`DELETE FROM "user" WHERE id = $1`, [sub]);
    await c.query(`INSERT INTO audit_log (actor_sub, action, target, detail) VALUES ($1, 'user.deleted', $2, $3)`, [
      actor, sub, JSON.stringify({ callsign: rows[0].callsign, reason }),
    ]);
    return rows[0].callsign;
  });
  return done !== null;
}

const hashToken = (t: string) => createHash("sha256").update(t).digest("base64url");

/**
 * Schedule self-deletion in GRACE_DAYS and sign the account out everywhere. Returns when it
 * happens. The email carries a link that cancels it without signing in.
 */
export async function scheduleDeletion(sub: string): Promise<Date> {
  const token = randomBytes(24).toString("base64url");
  const { rows } = await q<{ delete_after: Date; email: string; callsign: string }>(
    `WITH s AS (
       INSERT INTO account_deletion (sub, requested_at, delete_after, cancel_token_hash)
       VALUES ($1, now(), now() + make_interval(days => $2), $3)
       ON CONFLICT (sub) DO UPDATE SET cancel_token_hash = EXCLUDED.cancel_token_hash
       RETURNING delete_after)
     SELECT s.delete_after, u.email, u.callsign FROM s, "user" u WHERE u.id = $1`,
    [sub, GRACE_DAYS, hashToken(token)],
  );
  const r = rows[0]!;
  await q(`DELETE FROM session WHERE "userId" = $1`, [sub]);
  await q(`UPDATE "oauthRefreshToken" SET revoked = now() WHERE "userId" = $1 AND revoked IS NULL`, [sub]);
  await q(`INSERT INTO audit_log (actor_sub, action, target, detail) VALUES ($1, 'user.deletion_scheduled', $1, $2)`, [
    sub, JSON.stringify({ delete_after: r.delete_after }),
  ]);
  await sendMail(
    r.email,
    `openRMS: ${r.callsign} will be deleted on ${r.delete_after.toUTCString()}`,
    `You asked to delete your openRMS account ${r.callsign}. It will be deleted on ${r.delete_after.toUTCString()}, with everything openRMS services hold for it.\n\n` +
      `Changed your mind? Cancel here: ${env.UI_URL}/delete/cancel?token=${token}\n(or sign in and cancel on your account page).`,
  ).catch((e) => console.error("[deletion] mail failed", (e as Error).message));
  return r.delete_after;
}

export async function pendingDeletion(sub: string): Promise<Date | null> {
  const { rows } = await q<{ delete_after: Date }>(`SELECT delete_after FROM account_deletion WHERE sub = $1`, [sub]);
  return rows[0]?.delete_after ?? null;
}

/** Cancel by the signed-in owner (sub) or by the emailed token. */
export async function cancelDeletion(by: { sub: string } | { token: string }): Promise<string | null> {
  const { rows } = "sub" in by
    ? await q<{ sub: string }>(`DELETE FROM account_deletion WHERE sub = $1 RETURNING sub`, [by.sub])
    : await q<{ sub: string }>(`DELETE FROM account_deletion WHERE cancel_token_hash = $1 RETURNING sub`, [hashToken(by.token)]);
  const sub = rows[0]?.sub ?? null;
  if (sub) await q(`INSERT INTO audit_log (actor_sub, action, target) VALUES ($1, 'user.deletion_cancelled', $1)`, [sub]);
  return sub;
}

/** Delete accounts whose grace period is over. A club's only owner is not deleted: cancelled and told why. */
export async function runDueDeletions(): Promise<number> {
  const { rows } = await q<{ sub: string; email: string; callsign: string }>(
    `SELECT d.sub, u.email, u.callsign FROM account_deletion d JOIN "user" u ON u.id = d.sub WHERE d.delete_after <= now()`,
  );
  let n = 0;
  for (const r of rows) {
    const clubs = await soleOwnerOf(r.sub);
    if (clubs.length) {
      await cancelDeletion({ sub: r.sub });
      await sendMail(r.email, `openRMS: ${r.callsign} was not deleted`,
        `Your account wasn't deleted because you're now the only owner of ${clubs.join(", ")}. Make someone else owner (or delete the club), then ask again.`,
      ).catch(() => {});
      continue;
    }
    if (await deleteAccount(r.sub, r.sub, "self-service")) n++;
  }
  return n;
}

export function startDeletionJob(intervalMs = 15 * 60_000) {
  const run = () => runDueDeletions().catch((e) => console.error("[deletion] job failed", e));
  setTimeout(run, 60_000).unref();
  setInterval(run, intervalMs).unref();
}
