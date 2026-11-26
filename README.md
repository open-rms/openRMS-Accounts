# openRMS-Accounts

- **Provides:** single sign-on and shared profiles (callsign, clubs, staff roles) for all
  openRMS apps: OIDC / OAuth 2.1 issuer at `https://auth.openrms.dev`, account UI, events.
- **Consumes:** PostgreSQL, SMTP. Contract in `openRMS-Spec/accounts/identity.md`.
- **Status:** alpha (local only). Run: `pnpm install`, `pnpm build:ui` (account pages), `pnpm dev`
  (port 8789: API, OIDC endpoints and the pages /login, /signup, /link, /consent, /account,
  /clubs). See `PLAN.md`.

License: AGPL-3.0-or-later.
