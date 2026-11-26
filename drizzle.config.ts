import { defineConfig } from "drizzle-kit";

// Drizzle manages Accounts' own tables only. Better Auth's tables are created and migrated by
// Better Auth itself (src/migrate.ts), so they are excluded here.
export default defineConfig({
  dialect: "postgresql",
  schema: "./src/db/schema.ts",
  out: "./drizzle",
  dbCredentials: { url: process.env.DATABASE_URL ?? "postgres://openrms:openrms@127.0.0.1:5442/openrms_accounts" },
  tablesFilter: ["audit_log", "webhook_subscriber", "event_outbox", "event_delivery", "api_key", "profile"],
  strict: true,
  verbose: true,
});
