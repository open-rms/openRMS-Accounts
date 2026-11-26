// Migrations, run at startup and by `pnpm migrate`:
//   1. Better Auth migrates its own tables (user, session, organization, jwks, oauth*, deviceCode, ...).
//   2. One holder per callsign: unique indexes on user and organization.
//   3. Accounts' own tables: audit log, webhook subscribers, event outbox and deliveries.
import { getMigrations } from "better-auth/db/migration";
import { auth } from "./auth.js";
import { pool } from "./db/pool.js";

const OWN_TABLES = `
CREATE TABLE IF NOT EXISTS audit_log (
  id bigserial PRIMARY KEY,
  at timestamptz NOT NULL DEFAULT now(),
  actor_sub text,
  action text NOT NULL,
  target text NOT NULL,
  detail jsonb
);
CREATE TABLE IF NOT EXISTS webhook_subscriber (
  id text PRIMARY KEY DEFAULT gen_random_uuid()::text,
  name text NOT NULL UNIQUE,
  url text NOT NULL,
  secret text NOT NULL,
  active boolean NOT NULL DEFAULT true,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS event_outbox (
  id text PRIMARY KEY,
  type text NOT NULL,
  data jsonb NOT NULL,
  created_at timestamptz NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS event_delivery (
  event_id text NOT NULL REFERENCES event_outbox(id) ON DELETE CASCADE,
  subscriber_id text NOT NULL REFERENCES webhook_subscriber(id) ON DELETE CASCADE,
  attempts int NOT NULL DEFAULT 0,
  next_at timestamptz NOT NULL DEFAULT now(),
  delivered_at timestamptz,
  last_error text,
  PRIMARY KEY (event_id, subscriber_id)
);
CREATE INDEX IF NOT EXISTS event_delivery_due ON event_delivery (next_at) WHERE delivered_at IS NULL;
`;

export async function migrate() {
  const { runMigrations } = await getMigrations(auth.options);
  await runMigrations();
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS user_callsign_unique ON "user" (callsign)`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS organization_callsign_unique ON organization (callsign)`);
  await pool.query(OWN_TABLES);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  migrate()
    .then(() => { console.log("migrations applied"); return pool.end(); })
    .catch((e) => { console.error(e); process.exit(1); });
}
