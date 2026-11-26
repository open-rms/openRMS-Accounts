// openRMS-Accounts' own tables (Drizzle). Better Auth's tables (user, session, account,
// organization, member, jwks, oauth*, deviceCode, ...) are created and migrated by Better Auth
// itself (src/migrate.ts) and are excluded from Drizzle (drizzle.config.ts tablesFilter).
//
// Workflow: edit this file → `pnpm db:generate` (writes a versioned SQL migration into
// ./drizzle; review and commit it) → migrations apply at startup or with `pnpm migrate`.
import { sql } from "drizzle-orm";
import { bigserial, boolean, foreignKey, index, integer, jsonb, pgTable, primaryKey, text, timestamp, unique } from "drizzle-orm/pg-core";

// Constraint names match Postgres's defaults, so databases created before Drizzle (by the old
// CREATE TABLE IF NOT EXISTS) and after it are identical.
const ts = (name: string) => timestamp(name, { withTimezone: true, mode: "date" });

/** Who did what to which account, club or client. */
export const auditLog = pgTable("audit_log", {
  id: bigserial({ mode: "number" }).primaryKey(),
  at: ts("at").notNull().defaultNow(),
  actorSub: text("actor_sub"),
  action: text().notNull(),
  target: text().notNull(),
  detail: jsonb(),
});

/** A service that receives account events (identity.md §7). */
export const webhookSubscriber = pgTable(
  "webhook_subscriber",
  {
    id: text().primaryKey().default(sql`gen_random_uuid()::text`),
    name: text().notNull(),
    url: text().notNull(),
    secret: text().notNull(),
    active: boolean().notNull().default(true),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (t) => [unique("webhook_subscriber_name_key").on(t.name)],
);

/** Events written in the same transaction as the change, then delivered (outbox pattern). */
export const eventOutbox = pgTable("event_outbox", {
  id: text().primaryKey(),
  type: text().notNull(),
  data: jsonb().notNull(),
  createdAt: ts("created_at").notNull().defaultNow(),
});

/** Delivery state of one event to one subscriber, retried with backoff. */
export const eventDelivery = pgTable(
  "event_delivery",
  {
    eventId: text("event_id").notNull(),
    subscriberId: text("subscriber_id").notNull(),
    attempts: integer().notNull().default(0),
    nextAt: ts("next_at").notNull().defaultNow(),
    deliveredAt: ts("delivered_at"),
    lastError: text("last_error"),
  },
  (t) => [
    primaryKey({ name: "event_delivery_pkey", columns: [t.eventId, t.subscriberId] }),
    foreignKey({ name: "event_delivery_event_id_fkey", columns: [t.eventId], foreignColumns: [eventOutbox.id] }).onDelete("cascade"),
    foreignKey({ name: "event_delivery_subscriber_id_fkey", columns: [t.subscriberId], foreignColumns: [webhookSubscriber.id] }).onDelete("cascade"),
    index("event_delivery_due").on(t.nextAt).where(sql`${t.deliveredAt} IS NULL`),
  ],
);
