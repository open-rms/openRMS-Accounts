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
    /** The service audience this subscriber is, for events meant for one service (key.revoked). */
    audience: text(),
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

/**
 * API keys (identity.md §5). The key itself (a signed JWT) is shown once and never stored; this
 * is what the owner's list, renewal and revocation need.
 */
export const apiKey = pgTable(
  "api_key",
  {
    jti: text().primaryKey(),
    sub: text().notNull(),
    aud: text().notNull(),
    scopes: text().array().notNull(),
    name: text().notNull(),
    createdAt: ts("created_at").notNull().defaultNow(),
    expiresAt: ts("expires_at").notNull(),
    /** Lifetime in days, kept for renewal. */
    days: integer().notNull(),
    renewable: boolean().notNull().default(false),
    /** OAuth client that minted it (device flow), or null when made on the API keys page. */
    clientId: text("client_id"),
    replaces: text(),
    replacedBy: text("replaced_by"),
    lastUsedAt: ts("last_used_at"),
    revokedAt: ts("revoked_at"),
    /** revoked | revoke-all | renewed | banned | deleted */
    revokeReason: text("revoke_reason"),
    remindedDays: integer("reminded_days"),
  },
  (t) => [
    index("api_key_sub").on(t.sub),
    index("api_key_revoked").on(t.aud, t.revokedAt).where(sql`${t.revokedAt} IS NOT NULL`),
    index("api_key_expiring").on(t.expiresAt).where(sql`${t.revokedAt} IS NULL`),
  ],
);

/**
 * Profile fields beyond name and grid, and who may see each field (identity.md §4a). Name and
 * grid live on Better Auth's user row; their visibility lives here. Written only through
 * PUT /api/v1/me/profile, never through Better Auth's updateUser.
 */
export const profile = pgTable("profile", {
  sub: text().primaryKey(),
  bio: text(),
  city: text(),
  /** [{kind: "qrz" | "website" | "other", url}] */
  links: jsonb().notNull().default(sql`'[]'::jsonb`),
  /** {name, grid, city, bio, links, avatar}: "public" | "members" | "private"; missing = default. */
  visibility: jsonb().notNull().default(sql`'{}'::jsonb`),
  hidden: boolean().notNull().default(false),
  /** none (callsign monogram) | gravatar (opt-in) | url (the user's https image), served via the avatar proxy (§6a). */
  avatarSource: text("avatar_source").notNull().default("none"),
  avatarUrl: text("avatar_url"),
  updatedAt: ts("updated_at").notNull().defaultNow(),
});

/**
 * "My radios" (identity.md §4, §6): the user's radios, keyed to the Rigs/Hamlib catalog by
 * the model macro (RIG_MODEL_FTDX10), with the Hamlib number as a fallback should a macro be
 * renamed. The label is the user's own (one macro can cover several products).
 */
export const userRadio = pgTable(
  "user_radio",
  {
    id: text().primaryKey().default(sql`gen_random_uuid()::text`),
    sub: text().notNull(),
    model: text().notNull(),
    hamlibModel: integer("hamlib_model"),
    label: text().notNull(),
    isPrimary: boolean("is_primary").notNull().default(false),
    sortOrder: integer("sort_order").notNull().default(0),
    createdAt: ts("created_at").notNull().defaultNow(),
  },
  (t) => [index("user_radio_sub").on(t.sub, t.sortOrder)],
);

/** Self-service deletions waiting out their grace period (identity.md §4c). */
export const accountDeletion = pgTable("account_deletion", {
  sub: text().primaryKey(),
  requestedAt: ts("requested_at").notNull().defaultNow(),
  deleteAfter: ts("delete_after").notNull(),
  /** sha256 of the emailed cancel link's token. */
  cancelTokenHash: text("cancel_token_hash").notNull(),
});
