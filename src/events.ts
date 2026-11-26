// Webhooks to services (openRMS-Spec/accounts/identity.md §7). Events are written to an outbox
// in the same database; a dispatcher delivers them to every active subscriber, signed, with
// retries and backoff. Subscribers are added with `pnpm cli add-webhook NAME URL`.
import { randomUUID } from "node:crypto";
import type { PoolClient } from "pg";
import { signWebhook } from "@openrms/service-auth";
import { pool, q } from "./db/pool.js";

export type EventType =
  | "user.updated" | "user.callsign_verified" | "user.banned" | "user.unbanned" | "user.deleted"
  | "club.created" | "club.updated" | "club.deleted" | "club.member_added" | "club.member_removed" | "club.verified"
  | "key.revoked";

/**
 * Queue an event for every active subscriber, or with `audience` only for the subscriber that is
 * that service (its `audience` column, or else a URL on that origin). Pass the transaction client
 * to emit atomically.
 */
export async function emit(type: EventType, data: Record<string, unknown>, client?: PoolClient, audience?: string): Promise<string> {
  const id = randomUUID();
  const run = client ? client.query.bind(client) : pool.query.bind(pool);
  // Every club event names the club, so receivers never see a club without its callsign and
  // name, whatever order events arrive in. (club.deleted carries what the hook passed.)
  if (type.startsWith("club.") && typeof data.id === "string" && (data.name === undefined || data.callsign === undefined)) {
    const { rows } = await run(`SELECT name, callsign FROM organization WHERE id = $1`, [data.id]);
    if (rows[0]) data = { ...data, name: data.name ?? rows[0].name, callsign: data.callsign ?? rows[0].callsign };
  }
  await run(`INSERT INTO event_outbox (id, type, data) VALUES ($1, $2, $3)`, [id, type, JSON.stringify(data)]);
  if (audience) {
    await run(
      `INSERT INTO event_delivery (event_id, subscriber_id)
       SELECT $1, id FROM webhook_subscriber
        WHERE active AND (audience = $2 OR (audience IS NULL AND (url = $2 OR url LIKE $2 || '/%')))`,
      [id, audience.replace(/\/+$/, "")],
    );
    return id;
  }
  await run(
    `INSERT INTO event_delivery (event_id, subscriber_id) SELECT $1, id FROM webhook_subscriber WHERE active`,
    [id],
  );
  // Reconcile (GET /api/v1/users?updatedSince=) must see every change, including ones that
  // don't touch the user row: bump the affected accounts. A user's payload lists its clubs.
  if (typeof data.sub === "string") await run(`UPDATE "user" SET "updatedAt" = now() WHERE id = $1`, [data.sub]);
  if ((type === "club.verified" || type === "club.updated" || type === "club.deleted") && typeof data.id === "string") {
    await run(`UPDATE "user" SET "updatedAt" = now() WHERE id IN (SELECT "userId" FROM member WHERE "organizationId" = $1)`, [data.id]);
  }
  return id;
}

const BACKOFF_S = [10, 30, 120, 600, 1800, 3600, 3 * 3600, 6 * 3600, 12 * 3600, 24 * 3600];

export async function deliverDue(limit = 50): Promise<number> {
  const { rows } = await q<{
    event_id: string; subscriber_id: string; attempts: number; type: string; data: unknown; created_at: Date; url: string; secret: string;
  }>(
    `SELECT d.event_id, d.subscriber_id, d.attempts, e.type, e.data, e.created_at, s.url, s.secret
       FROM event_delivery d JOIN event_outbox e ON e.id = d.event_id JOIN webhook_subscriber s ON s.id = d.subscriber_id
      WHERE d.delivered_at IS NULL AND d.next_at <= now() AND d.attempts < $2 AND s.active
      ORDER BY e.created_at LIMIT $1`,
    [limit, BACKOFF_S.length + 1],
  );
  for (const r of rows) {
    const body = JSON.stringify({ id: r.event_id, type: r.type, createdAt: r.created_at.toISOString(), data: r.data });
    let error: string | null = null;
    try {
      const res = await fetch(r.url, {
        method: "POST",
        headers: { "content-type": "application/json", "openrms-signature": signWebhook(body, r.secret), "openrms-event": r.type },
        body,
        signal: AbortSignal.timeout(10_000),
      });
      if (!res.ok) error = `HTTP ${res.status}`;
    } catch (e) {
      error = (e as Error).message;
    }
    if (error) {
      const wait = BACKOFF_S[Math.min(r.attempts, BACKOFF_S.length - 1)]!;
      await q(
        `UPDATE event_delivery SET attempts = attempts + 1, last_error = $3, next_at = now() + make_interval(secs => $4)
          WHERE event_id = $1 AND subscriber_id = $2`,
        [r.event_id, r.subscriber_id, error.slice(0, 500), wait],
      );
    } else {
      await q(`UPDATE event_delivery SET attempts = attempts + 1, delivered_at = now(), last_error = NULL WHERE event_id = $1 AND subscriber_id = $2`, [
        r.event_id, r.subscriber_id,
      ]);
    }
  }
  return rows.length;
}

export function startDispatcher(intervalMs = 5000) {
  let busy = false;
  const t = setInterval(async () => {
    if (busy) return;
    busy = true;
    try {
      await deliverDue();
    } catch (e) {
      console.error("[events]", (e as Error).message);
    } finally {
      busy = false;
    }
  }, intervalMs);
  t.unref();
  return () => clearInterval(t);
}
