# openRMS-Accounts

**Role:** single sign-on and shared profiles for every openRMS app and service. The one place
that holds passwords, sessions, callsigns and their verification, clubs, and staff roles.
Everything else is a relying party. Contract: `openRMS-Spec/accounts/identity.md`.
**Binary:** `openrms-accounts` (TypeScript, Better Auth) · **License:** AGPL-3.0-or-later
**Host:** `https://auth.openrms.dev` (issuer; configurable for self-hosters)

## Why (decided 2026-11-25)

The Directory already runs Better Auth with callsign accounts, RBAC, clubs, API keys and
device linking. With Rigs and more apps coming, each one should not grow its own accounts or
lean on the Directory's internals. Accounts is extracted **now**, while all apps are alpha and
the data is small; the migration only gets harder later.

Better Auth 1.7.28 covers it with plugins we already use plus:
`@better-auth/oauth-provider` (OAuth 2.1 / OIDC provider: authorization code + PKCE, client
credentials, refresh, device code through the `device-authorization` plugin, custom id-token,
access-token and userinfo claims, discovery, JWKS through the `jwt` plugin, back-channel
logout) and `crossSubDomainCookies` for first-party apps on `*.openrms.dev`.
Later options: `@better-auth/passkey`, `two-factor`, `@better-auth/sso`.

## What moves here from the Directory

| Moves to Accounts | Stays in the Directory |
|---|---|
| `user`, `session`, `account`, `verification` tables; email and password, reset, email verification | Gateways, claims, watchers, sightings, imports, audit of directory actions |
| `callsign`, `callsignVerified`, `callsignVerifiedMethod`, `gridsquare` fields, one-holder-per-callsign rule (users **and** clubs) | Gateway ownership, now `owner_sub` / `owner_club_id` (no foreign key to auth tables) |
| Clubs (`organization`, `member`, `invitation`) and their hooks | `orms_` and `ormsw_` keys (service-owned, spec §5) |
| Site roles, rank rule, role assignment (`rbac.ts` ranks, `canAssign`, `outranks`), `rankGuard` | The Directory's own permission statements (`gateway`, `report`, `import`, `watcher`, `setting`, `optout`), mapped from the role claim |
| Device authorization (`openrms-watch`, later `rigctlweb`, `hamstack`) | Watch linking: `GET /api/v1/me/watchers`, `POST /api/v1/watch/link` (accept the device-flow JWT; spec §5) |
| CLI: `set-role`, `set-callsign`, user admin | CLI: imports, gateway admin |
| Future callsign proof (LoTW, license databases, on-air code) | Heard-on-air evidence (from Watch) offered to Accounts as a proof input later |

Becomes cross-service (spec §7 events): callsign uniqueness checks against clubs, gateway
cleanup on club deletion, re-checking gateways after a callsign change, bans.

## Account UI

**Done 2026-11-25 (AC2):** the pages live in `ui/` (SvelteKit static SPA, the Site's stack and
theme) and Accounts serves them: `/login`, `/signup`, `/forgot-password`, `/reset-password`,
`/link`, `/consent`, `/account` (profile, password, sessions, connected apps), `/clubs`.
`UI_URL` defaults to the issuer. A `next` link may only return to Accounts or to a trusted app
(`TRUSTED_ORIGINS`, named in `APPS`). Checked headless (sign-up, profile, clubs, safe and
unsafe `next`, device approval). The consent page is untested until a third-party client exists.

History: **during AC1 the Site kept hosting the account pages** (sign-in, sign-up, `/link`, account
settings) against Accounts' API: `UI_URL` points at the Site, which shares the cookie on
`.openrms.dev` (on `localhost`, cookies ignore the port). A consent page is only needed once a
third-party web client exists. Afterwards (AC2) the pages move into Accounts' own UI so a
self-hoster runs one login for every app.

Target: Accounts serves its own small UI (SvelteKit, same stack as the Site): sign-in, sign-up with
callsign, password reset, OAuth consent, device-link page (`/link`), account settings, clubs,
connected apps, sessions. The Site's account pages move here and the Site links to them, so a
self-hoster runs one login for every app.

## Deployment

Node + PostgreSQL. Own database `openrms_accounts`; it may share a Postgres instance with
other services, but no service reads another's database. Dev port **8789**. Env:
`BETTER_AUTH_URL`, `BETTER_AUTH_SECRET`, `DATABASE_URL`, `COOKIE_DOMAIN` (`.openrms.dev`),
`TRUSTED_ORIGINS`, SMTP settings.

## Status (2026-11-25)

AC1 steps 1, 2 and 5 are built and pass `ACCOUNTS_E2E=1 pnpm test` against a running server
(discovery, sign-up, first-party tokens, clubs and signed webhooks, service tokens and the
service API, Watch device flow bound to the Directory). Dev: `pnpm dev` on 8789, database
`openrms_accounts`; `pnpm import-directory` copied 4 accounts and 2 clubs; `pnpm cli
seed-clients` registered `openrms-watch`, `openrms-directory`, `openrms-rigs` (dev secrets in
the gitignored `.dev-clients.env`). Steps 3 and 4 are done by the Directory session: the
Directory no longer runs Better Auth (it verifies tokens, keeps its own `api_key` table with all
69 keys imported unchanged, and a webhook- and reconcile-fed account cache), and the Site signs
in through Accounts. Left for the exit test: Watch's device-flow switch (waiting for the user's
go). Old Better Auth tables are still in the Directory's dev database until the user approves
dropping them.

## Hosting choice (2026-11-25)

Accounts runs our own Better Auth, never a managed auth product. Neon's Managed Better Auth was
considered and ruled out: no custom fields, hooks, plugins or server code (Accounts needs the
callsign field and uniqueness hook, custom claims, device authorization, the club and service
APIs, webhooks), no documented export to self-hosted, and no documented custom domain for the
issuer. A hosted **plain Postgres** (Neon or any other) is fine for `DATABASE_URL`: moving back
is an ordinary dump and restore.

## Phases

- **AC0 (now):** spec `identity.md`, domain `auth.openrms.dev`, project registered. Agree the
  claims and events with the Directory, Site, Rigs and Watch sessions.
- **AC1, extract:**
  1. New service with the moved Better Auth config, plus `oauth-provider`, `jwt`,
     `crossSubDomainCookies`; account UI.
  2. One-time migration script copying the auth tables from the Directory database (ids kept,
     so existing `owner_user_id` values become `owner_sub` unchanged). Existing `orms_` and
     `ormsw_` keys are copied into the Directory's own table with the same hashes, so no
     deployed gateway or watcher needs re-linking.
  3. Directory (details in openRMS-Directory/PLAN.md, "Identity moving to openRMS-Accounts"):
     - verify JWTs via `@openrms/service-auth`; its permission table keys on the `role`
       claim, and role assignment and the rank rule leave the Directory;
     - own `api_key` table (id, kind `gateway`|`watcher` fixed at creation, prefix, start,
       hash, owner_sub, watcher_id / gateway_ids, rate-limit window and count, last_used_at,
       created_at, revoked_at). Better Auth stores `base64url(sha256(key))` unpadded, so the
       existing rows import as-is and nobody rotates;
     - local `account` cache (sub, callsign, callsign_verified, banned, club memberships), fed
       by webhooks plus a timed reconcile. It is used in SQL for gateway dedupe, club
       `ownerVerified`, sightings `confirmed` and the contributor list. Writes check it for
       membership and bans (spec §7);
     - `lib/access.ts` "callsigns you may act for": the caller's `clubs` claim, confirmed
       against the cache on writes;
     - foreign keys to `"user"` become text `*_sub` columns (or FKs to the cache), renamed
       in the same migration: owners, audit log actor, opt-outs, settings `created_by`;
     - device flow: the `device_link` table and `/watch/link/complete` go away, replaced by
       the token-based watcher pick (spec §5).
  4. Site: auth client points at `auth.openrms.dev`, gets JWTs for Directory calls.
  5. Shared TypeScript helper `@openrms/service-auth` in this repo:
     `verifyAccessToken(token, {audience})` returning the spec §4 claims, plus webhook
     verify and key hashing. Used by Directory and Rigs (Rigs swaps out its stub verifier).
  - Exit test: one sign-in at `auth.openrms.dev` works on the Site, the Directory API and Rigs;
    Watch links via device code and still gets its `ormsw_` key.
- **AC2:** ~~webhooks with outbox, Accounts API for services, Rigs onboarding, device clients
  `rigctlweb` and `hamstack`, move the account pages into Accounts' own UI~~ (done
  2026-11-25); Rust crate `openrms-auth` built (device flow; JWKS verification when a Rust
  service needs it), originally planned as: `openrms-auth` in openRMS-Libs (JWKS verify, device
  flow) for Watch and Gateway.
- **AC3:** passkeys, optional 2FA (required for staff), callsign proof methods, third-party
  client registration (admin approved first; dynamic registration later).
- **Later:** trust between issuers of self-hosted stacks (federation).

## Open questions

- ~~Q1~~ **Decided:** the Directory keeps its keys in its own table (Directory and Watch agree).
- ~~Q2~~ **Decided:** one subdomain per project. Directory is `directory.openrms.dev`
  (`aud` `https://directory.openrms.dev`); no generic `api.` host.
- **Q3:** Pin the exact JWT endpoint and audience (`resource`) behaviour of `oauth-provider`
  / `jwt` in 1.7 for the code grant and first-party tokens during AC1. Device grant: checked,
  it honours `resource`.
- **Q4:** How openRMS identity relates to nwl2k accounts, if the projects cooperate.
