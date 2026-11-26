// pnpm cli <command>
//   set-role CALL superadmin|admin|moderator|user
//   reset-2fa CALL            remove TOTP and passkeys, end sessions and refresh tokens (lost every factor)
//   set-callsign OLD NEW              moderator callsign change (services re-check via user.updated)
//   delete-user CALL [--force]        delete an account for good (emits user.deleted)
//   bootstrap CALL                    first deploy: make CALL superadmin, then seed-clients
//   seed-clients                      register the clients of spec §8 that don't exist yet
//   add-client ID NAME public|confidential|service [redirectUri ...]
//   list-clients
//   rename-client OLD NEW             change a client id, keeping its secret and links
//   link-resource CLIENT URL          let a client request tokens for a resource (unlink-resource to undo)
//   remove-client ID
//   add-webhook NAME URL              prints the signing secret once
//   list-webhooks
//   rename-webhook OLD NEW [URL]      rename a subscriber (same secret), optionally new URL
import { randomBytes } from "node:crypto";
import { existsSync, readFileSync, writeFileSync } from "node:fs";
import { auth, revokeUserTokens, withClientId } from "./auth.js";
import { pool, q, tx } from "./db/pool.js";
import { env } from "./env.js";
import { emit } from "./events.js";
import { isValidBaseCallsign, normalizeCallsign } from "./lib/callsign.js";
import { migrate } from "./migrate.js";
import { ROLE_NAMES, type RoleName } from "./rbac.js";
import { audit } from "./routes/admin.js";
import { hasSecondFactor } from "./staff.js";

type Kind = "public" | "confidential" | "service" | "first-party";

interface ClientSpec {
  id: string;
  name: string;
  kind: Kind;
  redirectUris?: string[];
  grants: string[];
  /** Resource servers the client may get tokens for (RFC 8707). */
  resources?: string[];
}

// Atlas's audiences among the configured resources (dev and production hosts).
const atlasResources = () => env.resources.filter((r) => /\/\/atlas\.|:8787$/.test(r));
const rigsResources = () => env.resources.filter((r) => /\/\/rigs\.|:8790$/.test(r));
const DEVICE = ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"];

/** Spec §8. Redirect URIs for browser clients are added per deployment with add-client. */
const SEED: ClientSpec[] = [
  { id: "openrms-watch", name: "openRMS Watch", kind: "public", grants: ["urn:ietf:params:oauth:grant-type:device_code", "refresh_token"], resources: atlasResources() },
  // Headless apps that act for a user at Rigs (spec §8).
  { id: "rigctlweb", name: "rigctlWeb", kind: "public", grants: DEVICE, resources: rigsResources() },
  { id: "hamstack", name: "hamstack", kind: "public", grants: DEVICE, resources: rigsResources() },
  { id: "openrms-atlas", name: "openRMS Atlas", kind: "service", grants: ["client_credentials"] },
  { id: "openrms-rigs", name: "openRMS Rigs", kind: "service", grants: ["client_credentials"] },
];

export async function registerClient(spec: ClientSpec): Promise<{ client_id: string; client_secret?: string }> {
  const isPublic = spec.kind === "public";
  const body = {
    client_name: spec.name,
    grant_types: spec.grants,
    token_endpoint_auth_method: isPublic ? "none" : "client_secret_basic",
    ...(spec.redirectUris?.length ? { redirect_uris: spec.redirectUris, response_types: ["code"] as ["code"] } : {}),
    ...(isPublic ? { application_type: "native" as const, require_pkce: true } : {}),
    ...(spec.grants.includes("client_credentials")
      ? { resources: [env.ISSUER, ...(spec.resources ?? [])], client_credentials_scopes: ["accounts.read"] }
      : spec.resources?.length ? { resources: spec.resources } : {}),
    // Only openRMS's own apps skip consent and get the staff `role` claim; a confidential
    // third-party web app is neither (spec §4).
    skip_consent: spec.kind === "service" || spec.kind === "first-party",
    metadata: { service: spec.kind === "service", firstParty: spec.kind === "service" || spec.kind === "first-party" },
  };
  const headers = await superadminHeaders();
  const res: unknown = await withClientId(spec.id, () => auth.api.adminCreateOAuthClient({ body, headers } as never));
  return (res instanceof Response ? await res.json() : res) as { client_id: string; client_secret?: string };
}

/** Client management needs a superadmin session: mint a short-lived one for the CLI. */
let cliHeaders: Headers | undefined;
async function superadminHeaders(): Promise<Headers> {
  if (cliHeaders) return cliHeaders;
  const { rows } = await q<{ id: string }>(`SELECT id FROM "user" WHERE role LIKE '%superadmin%' ORDER BY "createdAt" LIMIT 1`);
  if (!rows[0]) throw new Error("no superadmin yet: sign up, then pnpm cli set-role CALL superadmin");
  const ctx = await auth.$context;
  const session = await ctx.internalAdapter.createSession(rows[0].id, false, { expiresAt: new Date(Date.now() + 5 * 60_000) } as never);
  cliSessionToken = session.token;
  cliHeaders = new Headers({ authorization: `Bearer ${session.token}` });
  return cliHeaders;
}
let cliSessionToken: string | undefined;

/** Dev only: keep service client secrets in a gitignored file sibling services can read. */
function saveDevSecret(clientId: string, secret: string) {
  const file = new URL("../.dev-clients.env", import.meta.url);
  const key = clientId.toUpperCase().replace(/-/g, "_");
  const lines = existsSync(file) ? readFileSync(file, "utf8").split("\n").filter((l) => l && !l.startsWith(`${key}_CLIENT_`)) : ["# Dev-only OAuth client secrets (pnpm cli seed-clients). Never use in production."];
  lines.push(`${key}_CLIENT_ID=${clientId}`, `${key}_CLIENT_SECRET=${secret}`);
  writeFileSync(file, lines.join("\n") + "\n", { mode: 0o600 });
}

async function seedClients() {
  for (const spec of SEED) {
    const { rowCount } = await q(`SELECT 1 FROM "oauthClient" WHERE "clientId" = $1`, [spec.id]);
    if (rowCount) {
      console.log(`${spec.id}: exists`);
      continue;
    }
    const r = await registerClient(spec);
    if (r.client_secret && process.env.NODE_ENV !== "production") {
      saveDevSecret(r.client_id, r.client_secret);
      console.log(`${r.client_id}: created, secret saved to .dev-clients.env`);
    } else {
      console.log(`${r.client_id}: created${r.client_secret ? `, secret ${r.client_secret} (shown once; put it in that service's env)` : ""}`);
    }
  }
}

const [cmd, ...args] = process.argv.slice(2);
await migrate();

switch (cmd) {
  case "set-role": {
    const call = normalizeCallsign(args[0] ?? "");
    const role = args[1] ?? "";
    if (!ROLE_NAMES.includes(role as RoleName)) {
      console.log(`usage: set-role CALLSIGN ${ROLE_NAMES.join("|")}`);
      break;
    }
    const r = await q(`UPDATE "user" SET role = $2, "updatedAt" = now() WHERE callsign = $1 RETURNING id`, [call, role]);
    if (r.rowCount) {
      await audit(null, "role.set.cli", r.rows[0].id, role);
      await emit("user.updated", { sub: r.rows[0].id });
    }
    console.log(r.rowCount ? `${call} is now ${role}` : "no such callsign");
    if (r.rowCount && role !== "user" && !(await hasSecondFactor(r.rows[0].id))) {
      console.log(`note: ${call} has no second factor yet; with STAFF_2FA_REQUIRED on they act as "user" until they turn on 2FA or add a passkey`);
    }
    break;
  }
  case "reset-2fa": {
    // Last-resort recovery (spec §4b): every factor lost. Check who is asking out of band first.
    const call = normalizeCallsign(args[0] ?? "");
    const { rows } = await q<{ id: string }>(`SELECT id FROM "user" WHERE callsign = $1`, [call]);
    if (!rows[0]) {
      console.log(call ? "no such callsign" : "usage: reset-2fa CALLSIGN");
      break;
    }
    const id = rows[0].id;
    const tf = await q(`DELETE FROM "twoFactor" WHERE "userId" = $1`, [id]);
    const pk = await q(`DELETE FROM passkey WHERE "userId" = $1`, [id]);
    await q(`UPDATE "user" SET "twoFactorEnabled" = false, "updatedAt" = now() WHERE id = $1`, [id]);
    const ss = await q(`DELETE FROM session WHERE "userId" = $1`, [id]);
    await revokeUserTokens(id);
    await audit(null, "2fa.reset.cli", id, { totp: tf.rowCount, passkeys: pk.rowCount, sessions: ss.rowCount });
    await emit("user.updated", { sub: id });
    console.log(`${call}: 2FA off, ${pk.rowCount} passkey(s) removed, ${ss.rowCount} session(s) and every refresh token ended`);
    break;
  }
  case "set-callsign": {
    const oldC = normalizeCallsign(args[0] ?? "");
    const newC = normalizeCallsign(args[1] ?? "");
    if (!oldC || !isValidBaseCallsign(newC)) {
      console.log("usage: set-callsign OLDCALL NEWCALL");
      break;
    }
    const held = await q(`SELECT 1 FROM "user" WHERE callsign = $1 UNION ALL SELECT 1 FROM organization WHERE callsign = $1`, [newC]);
    if (held.rowCount) {
      console.log(`${newC} is already held by an account or club`);
      break;
    }
    const moved = await tx(async (c) => {
      const u = await c.query(
        `UPDATE "user" SET callsign = $2, "callsignVerified" = false, "callsignVerifiedMethod" = NULL, "updatedAt" = now() WHERE callsign = $1 RETURNING id`,
        [oldC, newC],
      );
      if (!u.rowCount) return null;
      // Services hide what was listed under the old callsign (Atlas: gateways).
      await emit("user.updated", { sub: u.rows[0].id, callsign: { from: oldC, to: newC } }, c);
      return u.rows[0].id as string;
    });
    if (moved) await audit(null, "callsign.set.cli", moved, { from: oldC, to: newC });
    console.log(moved ? `${oldC} is now ${newC} (unverified)` : "no such callsign");
    break;
  }
  case "delete-user": {
    // Permanent. Sessions, logins, tokens, consents and memberships go with the row (FK cascade).
    // Services drop their own data on user.deleted. Staff can also use POST /api/auth/admin/remove-user.
    const call = normalizeCallsign(args[0] ?? "");
    const force = args.includes("--force");
    if (!call) {
      console.log("usage: delete-user CALLSIGN [--force]");
      break;
    }
    const { rows: [u] } = await q<{ id: string; role: string | null }>(`SELECT id, role FROM "user" WHERE callsign = $1`, [call]);
    if (!u) {
      console.log("no such callsign");
      break;
    }
    const { rows: soleOwner } = await q<{ callsign: string }>(
      `SELECT o.callsign FROM member m JOIN organization o ON o.id = m."organizationId"
        WHERE m."userId" = $1 AND m.role LIKE '%owner%'
          AND (SELECT count(*) FROM member m2 WHERE m2."organizationId" = o.id AND m2.role LIKE '%owner%') = 1`,
      [u.id],
    );
    if (soleOwner.length && !force) {
      console.log(`${call} is the only owner of ${soleOwner.map((r) => r.callsign).join(", ")}. Make someone else owner first, or add --force (the club stays, without an owner).`);
      break;
    }
    if (/superadmin/.test(u.role ?? "") && !force) {
      console.log(`${call} is a superadmin; add --force to delete it anyway.`);
      break;
    }
    await tx(async (c) => {
      const { rows: clubs } = await c.query<{ id: string }>(`SELECT "organizationId" AS id FROM member WHERE "userId" = $1`, [u.id]);
      for (const club of clubs) await emit("club.member_removed", { id: club.id, sub: u.id }, c);
      await emit("user.deleted", { sub: u.id, callsign: call }, c);
      await c.query(`DELETE FROM "user" WHERE id = $1`, [u.id]);
    });
    await audit(null, "user.delete.cli", u.id, { callsign: call, force });
    console.log(`${call} deleted`);
    break;
  }
  case "bootstrap": {
    // A fresh deployment: make the first account (signed up on the site) superadmin, then
    // register the openRMS clients. Safe to run again.
    const call = normalizeCallsign(args[0] ?? "");
    const { rows: [u] } = await q<{ id: string }>(`SELECT id FROM "user" WHERE callsign = $1`, [call]);
    if (!u) {
      console.log("usage: bootstrap CALLSIGN  (sign up with that callsign on the site first)");
      break;
    }
    await q(`UPDATE "user" SET role = 'superadmin', "updatedAt" = now() WHERE id = $1`, [u.id]);
    await audit(null, "role.set.cli", u.id, "superadmin (bootstrap)");
    await emit("user.updated", { sub: u.id });
    console.log(`${call} is superadmin`);
    await seedClients();
    break;
  }
  case "seed-clients": {
    await seedClients();
    break;
  }
  case "add-client": {
    const [id, name, kind, ...redirectUris] = args;
    if (!id || !name || !["public", "confidential", "service", "first-party"].includes(kind ?? "")) {
      console.log("usage: add-client ID NAME public|confidential|service|first-party [redirectUri ...]");
      break;
    }
    const grants = kind === "service" ? ["client_credentials"] : ["authorization_code", "refresh_token"];
    const r = await registerClient({ id, name, kind: kind as Kind, redirectUris, grants });
    console.log(`${r.client_id}: created${r.client_secret ? `, secret ${r.client_secret} (shown once)` : ""}`);
    break;
  }
  case "remove-client": {
    const r = await q(`DELETE FROM "oauthClient" WHERE "clientId" = $1`, [args[0] ?? ""]);
    console.log(r.rowCount ? `${args[0]} removed` : "no such client");
    break;
  }
  case "rename-client": {
    // Keeps the client's secret, settings, resource links and tokens; only the id changes.
    const [from, to] = args;
    if (!from || !to) {
      console.log("usage: rename-client OLD_ID NEW_ID");
      break;
    }
    const done = await tx(async (c) => {
      const { rowCount } = await c.query(`SELECT 1 FROM "oauthClient" WHERE "clientId" = $1`, [from]);
      if (!rowCount) return `no client ${from}`;
      if ((await c.query(`SELECT 1 FROM "oauthClient" WHERE "clientId" = $1`, [to])).rowCount) return `${to} already exists`;
      const { rows } = await c.query<{ column_name: string }>(
        `SELECT column_name FROM information_schema.columns WHERE table_schema = 'public' AND table_name = 'oauthClient' AND column_name NOT IN ('id', 'clientId')`,
      );
      const cols = rows.map((r) => `"${r.column_name}"`).join(", ");
      // Child rows reference "clientId" without ON UPDATE CASCADE: insert the new row, move children, drop the old.
      await c.query(`INSERT INTO "oauthClient" (id, "clientId", ${cols}) SELECT gen_random_uuid()::text, $2, ${cols} FROM "oauthClient" WHERE "clientId" = $1`, [from, to]);
      for (const t of ["oauthClientResource", "oauthRefreshToken", "oauthAccessToken", "oauthConsent"]) {
        await c.query(`UPDATE "${t}" SET "clientId" = $2 WHERE "clientId" = $1`, [from, to]);
      }
      await c.query(`DELETE FROM "oauthClient" WHERE "clientId" = $1`, [from]);
      return null;
    });
    console.log(done ?? `${from} is now ${to} (same secret)`);
    break;
  }
  case "link-resource":
  case "unlink-resource": {
    // Which audiences a client may get tokens for (RFC 8707). The resource must be in RESOURCES.
    const [clientId, resource] = args;
    if (!clientId || !resource) {
      console.log(`usage: ${cmd} CLIENT_ID RESOURCE_URL`);
      break;
    }
    if (cmd === "unlink-resource") {
      const r = await q(`DELETE FROM "oauthClientResource" WHERE "clientId" = $1 AND "resourceId" = $2`, [clientId, resource]);
      console.log(r.rowCount ? `${clientId} unlinked from ${resource}` : "no such link");
      break;
    }
    if (!(await q(`SELECT 1 FROM "oauthResource" WHERE identifier = $1`, [resource])).rowCount) {
      console.log(`${resource} isn't a known resource: add it to RESOURCES and restart Accounts first`);
      break;
    }
    await q(
      `INSERT INTO "oauthClientResource" (id, "clientId", "resourceId", "createdAt") VALUES (gen_random_uuid()::text, $1, $2, now())
       ON CONFLICT ("clientId", "resourceId") DO NOTHING`,
      [clientId, resource],
    );
    console.log(`${clientId} may request ${resource}`);
    break;
  }
  case "list-clients": {
    const { rows } = await q(`SELECT "clientId", name, "grantTypes", "redirectUris", disabled FROM "oauthClient" ORDER BY "createdAt"`);
    console.table(rows);
    break;
  }
  case "add-webhook": {
    const [name, url] = args;
    if (!name || !url) {
      console.log("usage: add-webhook NAME URL");
      break;
    }
    const secret = randomBytes(32).toString("base64url");
    await q(
      `INSERT INTO webhook_subscriber (name, url, secret) VALUES ($1, $2, $3)
       ON CONFLICT (name) DO UPDATE SET url = EXCLUDED.url, secret = EXCLUDED.secret, active = true`,
      [name, url, secret],
    );
    console.log(`${name} -> ${url}\nsigning secret (shown once): ${secret}`);
    break;
  }
  case "rename-webhook": {
    // Keeps the signing secret and pending deliveries; optionally points it at a new URL.
    const [from, to, url] = args;
    if (!from || !to) {
      console.log("usage: rename-webhook OLD_NAME NEW_NAME [URL]");
      break;
    }
    const r = await q(`UPDATE webhook_subscriber SET name = $2, url = COALESCE($3, url) WHERE name = $1`, [from, to, url ?? null]);
    console.log(r.rowCount ? `webhook ${from} is now ${to}${url ? ` -> ${url}` : ""} (same secret)` : `no webhook ${from}`);
    break;
  }
  case "list-webhooks": {
    const { rows } = await q(
      `SELECT s.name, s.url, s.active,
              (SELECT count(*) FROM event_delivery d WHERE d.subscriber_id = s.id AND d.delivered_at IS NULL)::int AS pending
         FROM webhook_subscriber s ORDER BY s.name`,
    );
    console.table(rows);
    break;
  }
  default:
    console.log("usage: pnpm cli set-role CALL ROLE | reset-2fa CALL | set-callsign OLD NEW | delete-user CALL [--force] | bootstrap CALL | seed-clients | add-client ID NAME KIND [redirect...] | list-clients | rename-client OLD NEW | link-resource CLIENT URL | unlink-resource CLIENT URL | add-webhook NAME URL | rename-webhook OLD NEW [URL] | list-webhooks");
}
if (cliSessionToken) await q(`DELETE FROM session WHERE token = $1`, [cliSessionToken]);
await pool.end();
