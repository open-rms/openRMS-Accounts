// One-time AC1 migration: copy identity tables from the Directory database into Accounts.
// Ids are kept, so the Directory's owner_user_id values become owner_sub unchanged.
// Idempotent: existing rows (by id) are left alone. Sessions are not copied (everyone signs
// in again), API keys stay in the Directory (spec §5).
//
//   DIRECTORY_DATABASE_URL=postgres://.../openrms pnpm import-directory
import pg from "pg";
import { migrate } from "../src/migrate.js";
import { pool } from "../src/db/pool.js";

const TABLES = ["user", "account", "organization", "member", "invitation"] as const;
const source = new pg.Pool({ connectionString: process.env.DIRECTORY_DATABASE_URL ?? "postgres://openrms:openrms@127.0.0.1:5442/openrms" });

async function columns(p: pg.Pool, table: string): Promise<string[]> {
  const { rows } = await p.query<{ column_name: string }>(
    `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = $1`,
    [table],
  );
  return rows.map((r) => r.column_name);
}

await migrate();
for (const table of TABLES) {
  const src = await columns(source, table);
  if (!src.length) {
    console.log(`${table}: not in source, skipped`);
    continue;
  }
  const dst = new Set(await columns(pool, table));
  const cols = src.filter((c) => dst.has(c));
  const dropped = src.filter((c) => !dst.has(c));
  if (dropped.length) console.log(`${table}: source columns not in Accounts, dropped: ${dropped.join(", ")}`);
  const list = cols.map((c) => `"${c}"`).join(", ");
  const { rows } = await source.query(`SELECT ${list} FROM "${table}"`);
  let inserted = 0;
  for (const r of rows) {
    const vals = cols.map((c) => r[c]);
    const ph = cols.map((_, i) => `$${i + 1}`).join(", ");
    const res = await pool.query(`INSERT INTO "${table}" (${list}) VALUES (${ph}) ON CONFLICT (id) DO NOTHING`, vals);
    inserted += res.rowCount ?? 0;
  }
  console.log(`${table}: ${rows.length} in Directory, ${inserted} new in Accounts`);
}
await source.end();
await pool.end();
