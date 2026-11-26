// Migrations, run at startup and by `pnpm migrate`:
//   1. Better Auth migrates its own tables (user, session, organization, jwks, oauth*, deviceCode, ...).
//   2. One holder per callsign: unique indexes on user and organization.
//   3. Accounts' own tables (audit log, webhook subscribers, event outbox and deliveries): Drizzle
//      applies the versioned SQL migrations in ./drizzle (schema: src/db/schema.ts).
// A database created before Drizzle was adopted is marked as at the baseline (0000).
import { fileURLToPath } from "node:url";
import { getMigrations } from "better-auth/db/migration";
import { drizzle } from "drizzle-orm/node-postgres";
import { migrate as drizzleMigrate } from "drizzle-orm/node-postgres/migrator";
import { readMigrationFiles } from "drizzle-orm/migrator";
import { auth } from "./auth.js";
import { pool } from "./db/pool.js";

const migrationsFolder = fileURLToPath(new URL("../drizzle", import.meta.url));

async function adoptBaseline() {
  const { rows } = await pool.query(
    `SELECT to_regclass('drizzle.__drizzle_migrations') IS NOT NULL AS tracked, to_regclass('public.event_delivery') IS NOT NULL AS existing`,
  );
  if (rows[0].tracked || !rows[0].existing) return;
  const [baseline] = readMigrationFiles({ migrationsFolder });
  if (!baseline) return;
  await pool.query(`CREATE SCHEMA IF NOT EXISTS drizzle`);
  await pool.query(`CREATE TABLE IF NOT EXISTS drizzle.__drizzle_migrations (id SERIAL PRIMARY KEY, hash text NOT NULL, created_at bigint)`);
  await pool.query(`INSERT INTO drizzle.__drizzle_migrations (hash, created_at) VALUES ($1, $2)`, [baseline.hash, baseline.folderMillis]);
  console.log("[migrate] existing database marked as at the Drizzle baseline");
}

export async function migrate() {
  const { runMigrations } = await getMigrations(auth.options);
  await runMigrations();
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS user_callsign_unique ON "user" (callsign)`);
  await pool.query(`CREATE UNIQUE INDEX IF NOT EXISTS organization_callsign_unique ON organization (callsign)`);
  await adoptBaseline();
  await drizzleMigrate(drizzle(pool), { migrationsFolder });
  // Drizzle doesn't know Better Auth's user table: tie profile rows to their account here.
  await pool.query(`DO $$ BEGIN
    ALTER TABLE profile ADD CONSTRAINT profile_sub_fkey FOREIGN KEY (sub) REFERENCES "user"(id) ON DELETE CASCADE;
  EXCEPTION WHEN duplicate_object THEN NULL; END $$`);
  await pool.query(`DO $$ BEGIN
    ALTER TABLE user_radio ADD CONSTRAINT user_radio_sub_fkey FOREIGN KEY (sub) REFERENCES "user"(id) ON DELETE CASCADE;
  EXCEPTION WHEN duplicate_object THEN NULL; END $$`);
}

if (import.meta.url === `file://${process.argv[1]}`) {
  migrate()
    .then(() => { console.log("migrations applied"); return pool.end(); })
    .catch((e) => { console.error(e); process.exit(1); });
}
