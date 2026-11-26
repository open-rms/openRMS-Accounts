// API keys end to end (spec §5) against a running Accounts (pnpm dev) and its database.
//   ACCOUNTS_E2E=1 pnpm test
// Needs seeded clients (pnpm cli seed-clients) and .dev-clients.env for the Atlas service secret.
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { RevocationSync, verifyAccessToken, verifyBearer, verifyWebhook, type AccountsEvent, type RevokedKey } from "@openrms/service-auth";
import { pool, q } from "../src/db/pool.js";

const BASE = process.env.ACCOUNTS_URL ?? "http://localhost:8789";
const ATLAS = "http://localhost:8787";
const RIGS = "http://localhost:8790";
const run = process.env.ACCOUNTS_E2E ? describe : describe.skip;

const devClients = (() => {
  try {
    return Object.fromEntries(
      readFileSync(new URL("../.dev-clients.env", import.meta.url), "utf8").split("\n").filter((l) => l.includes("=") && !l.startsWith("#")).map((l) => l.split("=", 2) as [string, string]),
    );
  } catch {
    return {} as Record<string, string>;
  }
})();

const letters = () => Array.from({ length: 3 }, () => String.fromCharCode(65 + Math.floor(Math.random() * 26))).join("");
const callsign = `N5${letters()}`;
let cookie = "";

async function api(path: string, init: { method?: string; json?: unknown; form?: Record<string, string>; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = { origin: "http://localhost:5173", ...(cookie ? { cookie } : {}), ...(init.headers ?? {}) };
  let body: string | undefined;
  if (init.json !== undefined) {
    headers["content-type"] = "application/json";
    body = JSON.stringify(init.json);
  } else if (init.form) {
    headers["content-type"] = "application/x-www-form-urlencoded";
    body = new URLSearchParams(init.form).toString();
  }
  const res = await fetch(`${BASE}${path}`, { method: init.method ?? (body ? "POST" : "GET"), headers, body });
  const text = await res.text();
  let parsed: any = text;
  try { parsed = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, body: parsed, headers: res.headers };
}

const denied = new Set<string>();
const isRevoked = (jti: string) => denied.has(jti);

run("API keys (spec §5)", () => {
  const events: AccountsEvent[] = [];
  const secret = "keys-e2e-" + letters();
  let sub = "";
  const hook = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => (raw += d));
    req.on("end", () => {
      try {
        events.push(verifyWebhook(raw, req.headers["openrms-signature"] as string, secret));
        res.writeHead(200).end();
      } catch {
        res.writeHead(400).end();
      }
    });
  });

  beforeAll(async () => {
    await new Promise<void>((r) => hook.listen(0, r));
    const port = (hook.address() as { port: number }).port;
    // Acts as Atlas's webhook: key.revoked for Atlas keys only.
    await q(
      `INSERT INTO webhook_subscriber (name, url, secret, audience) VALUES ('keys-e2e', $1, $2, $3)
       ON CONFLICT (name) DO UPDATE SET url = EXCLUDED.url, secret = EXCLUDED.secret, audience = EXCLUDED.audience, active = true`,
      [`http://localhost:${port}/hook`, secret, ATLAS],
    );
    const r = await api("/api/auth/sign-up/email", {
      json: { email: `${callsign.toLowerCase()}@example.test`, password: "correct horse battery", name: "Keys E2E", callsign },
    });
    expect(r.status).toBe(200);
    cookie = (r.headers.getSetCookie() ?? []).map((c) => c.split(";")[0]).join("; ");
    sub = r.body.user.id;
  });

  afterAll(async () => {
    await q(`DELETE FROM webhook_subscriber WHERE name = 'keys-e2e'`);
    await q(`DELETE FROM api_key WHERE sub = $1`, [sub]);
    await q(`DELETE FROM "user" WHERE callsign = $1`, [callsign]);
    hook.close();
    await pool.end();
  });

  const waitFor = async (pred: () => boolean, ms = 12_000) => {
    const until = Date.now() + ms;
    while (!pred() && Date.now() < until) await new Promise((r) => setTimeout(r, 250));
    return pred();
  };

  let heartbeatKey = "", heartbeatJti = "";

  it("lists services with their key scopes and mints a key shown once", async () => {
    const list = await api("/api/v1/me/keys");
    expect(list.status).toBe(200);
    expect(list.body.canCreate).toBe(true);
    const atlas = list.body.services.find((s: { aud: string }) => s.aud === ATLAS);
    expect(atlas.scopes.map((s: { scope: string }) => s.scope)).toContain("heartbeat");
    const r = await api("/api/v1/me/keys", { json: { aud: ATLAS, scopes: ["heartbeat"], name: "W1AW gateway", days: 90 } });
    expect(r.status, JSON.stringify(r.body)).toBe(201);
    expect(r.body.key).toMatch(/^ormk_ey/);
    heartbeatKey = r.body.key;
    heartbeatJti = r.body.jti;
    const again = await api("/api/v1/me/keys");
    const row = again.body.keys.find((k: { jti: string }) => k.jti === heartbeatJti);
    expect(row).toMatchObject({ name: "W1AW gateway", scopes: ["heartbeat"], aud: ATLAS });
    expect(JSON.stringify(again.body)).not.toContain(heartbeatKey.slice(5)); // never shown again
  });

  it("verifies offline with verifyBearer; access-token checks refuse keys", async () => {
    const b = await verifyBearer(`Bearer ${heartbeatKey}`.slice(7), { audience: ATLAS, issuers: [BASE], isRevoked });
    expect(b.kind).toBe("key");
    if (b.kind !== "key") return;
    expect(b.claims).toMatchObject({ sub, aud: ATLAS, scope: ["heartbeat"], jti: heartbeatJti, token_use: "api_key", callsign });
    expect(b.claims.exp - Math.floor(Date.now() / 1000)).toBeGreaterThan(89 * 86400);
    await expect(verifyAccessToken(heartbeatKey, { audience: ATLAS, issuers: [BASE] })).rejects.toThrow(/API keys/);
    await expect(verifyAccessToken(heartbeatKey.slice(5), { audience: ATLAS, issuers: [BASE] })).rejects.toThrow(/API keys/);
    await expect(verifyBearer(heartbeatKey, { audience: RIGS, issuers: [BASE], isRevoked })).rejects.toMatchObject({ code: "wrong_audience" });
    // A normal access token still passes verifyBearer as kind "access".
    const t = await api(`/api/v1/token?aud=${encodeURIComponent(ATLAS)}`);
    expect((await verifyBearer(t.body.token, { audience: ATLAS, issuers: [BASE], isRevoked })).kind).toBe("access");
  });

  it("refuses scopes a service doesn't offer for keys, and bad expiry", async () => {
    expect((await api("/api/v1/me/keys", { json: { aud: ATLAS, scopes: ["gateway:hide"], name: "x" } })).status).toBe(400);
    expect((await api("/api/v1/me/keys", { json: { aud: ATLAS, scopes: ["profiles:write"], name: "x" } })).status).toBe(400);
    expect((await api("/api/v1/me/keys", { json: { aud: ATLAS, scopes: ["heartbeat"], name: "x", days: 400 } })).status).toBe(400);
    expect((await api("/api/v1/me/keys", { json: { aud: "https://evil.example", scopes: ["heartbeat"], name: "x" } })).status).toBe(400);
  });

  it("revocation reaches the service by webhook and by pull (RevocationSync), with last use reported back", async () => {
    const id = devClients.OPENRMS_ATLAS_CLIENT_SECRET;
    expect(id, "run pnpm cli seed-clients and keep .dev-clients.env").toBeTruthy();
    const stored: RevokedKey[] = [];
    const sync = new RevocationSync({
      issuer: BASE, clientId: "openrms-atlas", clientSecret: devClients.OPENRMS_ATLAS_CLIENT_SECRET!,
      store: async (keys) => { for (const k of keys) { stored.push(k); denied.add(k.jti); } },
      lastSync: async () => null,
    });
    // Last use, batched by the service.
    const tok = await api("/api/auth/oauth2/token", {
      headers: { authorization: `Basic ${Buffer.from(`openrms-atlas:${devClients.OPENRMS_ATLAS_CLIENT_SECRET}`).toString("base64")}` },
      form: { grant_type: "client_credentials", resource: BASE, scope: "accounts.keys" },
    });
    expect(tok.status, JSON.stringify(tok.body)).toBe(200);
    const svc = { authorization: `Bearer ${tok.body.access_token}`, cookie: "" };
    const used = await api("/api/v1/keys/used", { json: [{ jti: heartbeatJti, at: new Date().toISOString() }], headers: svc });
    expect(used.body.recorded).toBe(1);
    const listed = await api(`/api/v1/users/${sub}/keys`, { headers: svc });
    expect(listed.status, JSON.stringify(listed.body)).toBe(200);
    expect(listed.body.keys[0].last_used_at).toBeTruthy();
    // A user's session can't use the service routes.
    expect((await api("/api/v1/keys/revoked?since=1970-01-01T00:00:00Z")).status).toBe(401);

    const del = await api(`/api/v1/me/keys/${heartbeatJti}`, { method: "DELETE" });
    expect(del.status).toBe(204);
    expect(await waitFor(() => events.some((e) => e.type === "key.revoked" && (e.data as { jti: string }).jti === heartbeatJti))).toBe(true);
    const ev = events.find((e) => e.type === "key.revoked")!;
    expect(ev.data).toMatchObject({ jti: heartbeatJti, aud: ATLAS, sub });
    expect(await sync.ingest(ev)).toBe(true);
    expect(denied.has(heartbeatJti)).toBe(true);
    denied.clear();
    expect(await sync.pull()).toBeGreaterThanOrEqual(1);
    expect(stored.some((k) => k.jti === heartbeatJti && typeof k.exp === "number")).toBe(true);
    await expect(verifyBearer(heartbeatKey, { audience: ATLAS, issuers: [BASE], isRevoked })).rejects.toMatchObject({ code: "revoked" });
  });

  it("Watch mints a renewable key through the device flow and renews it (chain, retry window)", async () => {
    const start = await api("/api/auth/device/code", { form: { client_id: "openrms-watch", scope: "openid keys", resource: BASE } });
    expect(start.status, JSON.stringify(start.body)).toBe(200);
    expect((await api(`/api/auth/device?user_code=${encodeURIComponent(start.body.user_code)}`)).status).toBe(200);
    expect((await api("/api/auth/device/approve", { json: { userCode: start.body.user_code } })).status).toBe(200);
    await new Promise((r) => setTimeout(r, (start.body.interval ?? 5) * 1000 + 300));
    const tok = await api("/api/auth/oauth2/token", {
      form: { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: start.body.device_code, client_id: "openrms-watch" },
    });
    expect(tok.status, JSON.stringify(tok.body)).toBe(200);
    const dev = { authorization: `Bearer ${tok.body.access_token}`, cookie: "" };
    // Outside the client's policy.
    expect((await api("/api/v1/keys", { json: { aud: ATLAS, scopes: ["heartbeat"], name: "w" }, headers: dev })).status).toBe(403);
    expect((await api("/api/v1/keys", { json: { aud: RIGS, scopes: ["favorites"], name: "w" }, headers: dev })).status).toBe(403);
    const m = await api("/api/v1/keys", { json: { aud: ATLAS, scopes: ["watch:ingest"], name: "Watcher DN16", expires_in_days: 365 }, headers: dev });
    expect(m.status, JSON.stringify(m.body)).toBe(201);
    expect(m.body.renewable).toBe(true);
    const first = m.body.key as string;

    const r1 = await api("/api/v1/keys/renew", { headers: { authorization: `Bearer ${first}`, cookie: "" }, method: "POST" });
    expect(r1.status, JSON.stringify(r1.body)).toBe(201);
    const b1 = await verifyBearer(r1.body.key, { audience: ATLAS, issuers: [BASE], isRevoked });
    expect(b1.kind === "key" && b1.claims.replaces).toBe(m.body.jti);
    expect(b1.kind === "key" && b1.claims.scope).toEqual(["watch:ingest"]);
    // Lost response: the old key may retry once more within the window; the first replacement dies.
    const r2 = await api("/api/v1/keys/renew", { headers: { authorization: `Bearer ${first}`, cookie: "" }, method: "POST" });
    expect(r2.status, JSON.stringify(r2.body)).toBe(201);
    const { rows } = await q(`SELECT jti, revoked_at, revoke_reason, replaced_by FROM api_key WHERE jti = ANY($1)`, [[m.body.jti, r1.body.jti, r2.body.jti]]);
    const by = Object.fromEntries(rows.map((r) => [r.jti, r]));
    expect(by[m.body.jti].replaced_by).toBe(r2.body.jti);
    expect(by[r1.body.jti].revoke_reason).toBe("renewed");
    expect(by[r2.body.jti].revoked_at).toBeNull();
    // Keys made on the page don't renew themselves.
    const page = await api("/api/v1/me/keys", { json: { aud: ATLAS, scopes: ["gateways:read"], name: "read" } });
    expect((await api("/api/v1/keys/renew", { headers: { authorization: `Bearer ${page.body.key}`, cookie: "" }, method: "POST" })).status).toBe(403);
    // A key can't mint keys.
    expect((await api("/api/v1/keys", { json: { aud: ATLAS, scopes: ["watch:ingest"], name: "w" }, headers: { authorization: `Bearer ${r2.body.key}`, cookie: "" } })).status).toBe(401);
  }, 30_000);

  it("revoke all ends every key, the renewal chain included", async () => {
    const r = await api("/api/v1/me/keys/revoke-all", { json: {} });
    expect(r.status).toBe(200);
    expect(r.body.revoked).toBeGreaterThanOrEqual(2);
    const { rows } = await q(`SELECT count(*)::int AS n FROM api_key WHERE sub = $1 AND revoked_at IS NULL`, [sub]);
    expect(rows[0].n).toBe(0);
  });

  it("a ban revokes the account's keys", async () => {
    const m = await api("/api/v1/me/keys", { json: { aud: RIGS, scopes: ["favorites"], name: "rigs" } });
    expect(m.status).toBe(201);
    // Ban straight through Better Auth's admin API as a superadmin would; simulate with the hook path's effect.
    const { revokeAllKeys } = await import("../src/keys.js");
    await revokeAllKeys(sub, "banned");
    const { rows } = await q(`SELECT revoke_reason FROM api_key WHERE jti = $1`, [m.body.jti]);
    expect(rows[0].revoke_reason).toBe("banned");
    // Rigs' key.revoked goes to Rigs' subscriber, not to Atlas's.
    await new Promise((r) => setTimeout(r, 6000));
    expect(events.some((e) => e.type === "key.revoked" && (e.data as { jti: string }).jti === m.body.jti)).toBe(false);
  }, 20_000);
});
