# openRMS-Accounts

- **Provides:** single sign-on and shared profiles (callsign, clubs, staff roles) for all
  openRMS apps: OIDC / OAuth 2.1 issuer at `https://auth.openrms.dev`, account UI, events.
- **Consumes:** PostgreSQL, SMTP. Contract in `openRMS-Spec/accounts/identity.md`.
- **Status:** alpha (local only). Run: `pnpm install`, `pnpm build:ui` (account pages), `pnpm dev`
  (port 8789: API, OIDC endpoints and the pages /login, /signup, /link, /consent, /account,
  /clubs). See `PLAN.md`.

## Database

Any PostgreSQL 16+ server works: local Docker, a managed host or your own. The service needs
only its own database and role; it never reads another service's database. Create them once
as an admin role, then point `DATABASE_URL` at the new database (add `?sslmode=require` for a
remote server). Migrations run at startup and with `pnpm migrate`.

```sh
psql "$ADMIN_DATABASE_URL" -v password="$(openssl rand -base64 24)" -f db/bootstrap.sql
```

Better Auth creates and migrates its own tables. Accounts' own tables (audit log, webhook
subscribers, event outbox and deliveries) are defined in `src/db/schema.ts` (Drizzle) and change
through versioned SQL migrations in `drizzle/`: edit the schema, run `pnpm db:generate`, review
and commit the new file. A database created before Drizzle was adopted is marked as at the
baseline automatically.

## Configuration

Every default is local (`localhost`). A deployment sets its own public URLs in the
environment: `BETTER_AUTH_URL` (the issuer), `TRUSTED_ORIGINS`, `APPS`, `FIRST_PARTY_AUDIENCES`,
`RESOURCES` and `COOKIE_DOMAIN`. See `.env.example`.

License: AGPL-3.0-or-later.
