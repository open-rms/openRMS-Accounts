# openRMS-Accounts

Single sign-on for openRMS: one account with your callsign for every openRMS app.

- **Provides:** an identity service (Better Auth as an OIDC / OAuth 2.1 issuer, production
  `https://auth.openrms.dev`): sign-in and shared profiles (callsign and its verification,
  clubs and extra callsigns, staff roles), first-party tokens per service, the device flow for
  headless apps (RFC 8628 with RFC 8707 resources), a service API, signed webhooks, and the
  account pages (`/login`, `/signup`, `/link`, `/consent`, `/account`, `/clubs`).
- **Consumes:** PostgreSQL, SMTP. The contract is `openRMS-Spec/accounts/identity.md`.
- **Used by:** openRMS Atlas (formerly the Directory) and its Site, Rigs and Watch, later Gateway, Exchange and third parties.
- **Status:** alpha, running locally; not yet deployed.

## Quick start

```sh
pnpm install
pnpm build:ui          # the account pages (ui/)
cp .env.example .env   # set BETTER_AUTH_SECRET (openssl rand -base64 32)
pnpm dev               # http://localhost:8789
pnpm cli bootstrap CALL   # first run: make your signed-up account superadmin and register the openRMS clients
ACCOUNTS_E2E=1 pnpm test   # end-to-end tests against the running server
```

## What's in here

| Path | What |
|---|---|
| `src/` | The service: Better Auth config (`auth.ts`), token claims, staff roles (`rbac.ts`), event outbox and webhooks, routes |
| `ui/` | The account pages: SvelteKit static SPA, served by the service |
| `packages/service-auth` | `@openrms/service-auth`: what other services use to trust Accounts (verify access tokens and `ormk_` API keys offline against JWKS with `verifyBearer`, keep the key denylist current with `RevocationSync`, verify webhooks). **MPL-2.0** |
| `scripts/` | One-off migrations (`import-from-directory.ts`) |
| `db/bootstrap.sql` | Creates the service's role and database on any PostgreSQL 16+ |

`@openrms/service-auth` isn't published to npm yet. Atlas and Rigs depend on it with
`link:../openRMS-Accounts/packages/service-auth`, so they need this repo checked out next to
them. How it gets distributed is still to be decided.

## Database

Any PostgreSQL 16+ server works: local Docker, a managed host or your own. The service needs
only its own database and role; it never reads another service's database. Create them once
as an admin role, then point `DATABASE_URL` at the new database (add `?sslmode=verify-full` for a
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

- `HOST` (default `127.0.0.1`): Accounts listens on loopback; put a reverse proxy or tunnel in
  front for the public URL. Set `0.0.0.0` or `::` only if it must listen on every interface.
- `TRUSTED_IP_HEADERS` (default empty: Better Auth's own default): the header your proxy sets
  with the real client IP, for per-IP rate limits, e.g. `cf-connecting-ip` behind Cloudflare
  Tunnel. Clients can forge these headers, so set it only when Accounts is reachable solely
  through that proxy (`HOST=127.0.0.1`). `TRUSTED_PROXIES` lists proxy IPs or CIDRs when a
  header carries a forwarded chain.
- `SMTP_URL` and `MAIL_FROM`: password-reset and verification mail. Unset, mail is logged.
  Cloudflare Email Sending: `smtps://api_token:<token>@smtp.mx.cloudflare.net:465`.
- `STAFF_2FA_REQUIRED` (default `false`): staff (moderator and up) need TOTP or a passkey, or
  they act as `user` everywhere (spec §4b). Deploy with it off, have every staff account enrol
  under Account → Sign-in security, then turn it on.

API keys (spec §5): people make them at `/keys`; Watch mints a renewable Atlas key through the
device flow. Services verify keys offline and learn revocations from the `key.revoked` webhook
(sent only to the key's service: set each subscriber's audience with `set-webhook-audience`) and
from `GET /api/v1/keys/revoked`. Key scopes come from each service's
`/.well-known/oauth-protected-resource` (`openrms_key_scopes`), with the spec's lists built in
until a service publishes them.

Operator commands (`pnpm cli …`): `bootstrap CALL`, `set-role CALL ROLE`, `set-callsign OLD NEW`,
`reset-2fa CALL [--revoke-keys]` (every factor lost: removes TOTP and passkeys, ends sessions; confirm who is asking first),
`delete-user CALL [--force]` (emits `user.deleted`; staff can also use
`POST /api/auth/admin/remove-user`), `seed-clients`, `add-client`, `list-clients`, `rename-client OLD NEW`,
`link-resource CLIENT URL` / `unlink-resource`,
`add-webhook NAME URL [AUDIENCE]`, `set-webhook-audience NAME [AUDIENCE]`, `rename-webhook OLD NEW [URL]`, `list-webhooks`.

## License

AGPL-3.0-or-later (`LICENSE`), except `packages/service-auth`, which is MPL-2.0 so any app
can use it.
