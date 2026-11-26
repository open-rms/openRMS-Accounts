// End-to-end against a running Accounts (pnpm dev) and its database.
//   ACCOUNTS_E2E=1 pnpm test
// Needs the seeded clients (pnpm cli seed-clients) and .dev-clients.env for the service secret.
import { createServer } from "node:http";
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { verifyAccessToken, verifyWebhook, type AccountsEvent } from "@openrms/service-auth";
import { auth } from "../src/auth.js";
import { pool, q } from "../src/db/pool.js";

const BASE = process.env.ACCOUNTS_URL ?? "http://localhost:8789";
const DIRECTORY = "http://localhost:8787";
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
const callsign = `N9${letters()}`;
const clubCall = `W9${letters()}`;
let cookie = "";
let deviceRefresh = "";

async function api(path: string, init: RequestInit = {}) {
  const res = await fetch(`${BASE}${path}`, { ...init, headers: { origin: "http://localhost:5173", ...(cookie ? { cookie } : {}), ...(init.headers ?? {}) } });
  const text = await res.text();
  let body: any = text;
  try { body = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, body, headers: res.headers };
}

const FORM = { "content-type": "application/x-www-form-urlencoded" };
const form = (o: Record<string, string>) => ({ headers: FORM, body: new URLSearchParams(o).toString() });

run("openRMS Accounts e2e", () => {
  const events: AccountsEvent[] = [];
  const secretHolder = { secret: "" };
  const hook = createServer((req, res) => {
    let raw = "";
    req.on("data", (d) => (raw += d));
    req.on("end", () => {
      try {
        events.push(verifyWebhook(raw, req.headers["openrms-signature"] as string, secretHolder.secret));
        res.writeHead(200).end();
      } catch {
        res.writeHead(400).end();
      }
    });
  });

  beforeAll(async () => {
    await new Promise<void>((r) => hook.listen(0, r));
    const port = (hook.address() as { port: number }).port;
    secretHolder.secret = "e2e-secret-" + letters();
    await q(
      `INSERT INTO webhook_subscriber (name, url, secret) VALUES ('e2e', $1, $2) ON CONFLICT (name) DO UPDATE SET url = EXCLUDED.url, secret = EXCLUDED.secret, active = true`,
      [`http://localhost:${port}/hook`, secretHolder.secret],
    );
  });

  afterAll(async () => {
    await q(`DELETE FROM webhook_subscriber WHERE name = 'e2e'`);
    await q(`DELETE FROM "user" WHERE callsign = $1`, [callsign]);
    hook.close();
    await pool.end();
  });

  it("serves discovery at the issuer root", async () => {
    const { status, body } = await api("/.well-known/openid-configuration");
    expect(status).toBe(200);
    expect(body.issuer).toBe(BASE);
    expect(body.grant_types_supported).toContain("urn:ietf:params:oauth:grant-type:device_code");
  });

  it("signs up with a callsign and refuses a duplicate", async () => {
    const r = await api("/api/auth/sign-up/email", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: `${callsign.toLowerCase()}@example.test`, password: "correct horse battery", name: "E2E", callsign: callsign.toLowerCase() }),
    });
    expect(r.status).toBe(200);
    cookie = (r.headers.getSetCookie() ?? []).map((c) => c.split(";")[0]).join("; ");
    expect(cookie).toContain("session_token");
    const dup = await api("/api/auth/sign-up/email", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email: `x${callsign.toLowerCase()}@example.test`, password: "correct horse battery", name: "Dup", callsign }),
    });
    expect(dup.status).toBe(400);
  });

  it("issues first-party tokens for one service at a time (spec §3a)", async () => {
    const r = await api(`/api/v1/token?aud=${encodeURIComponent(DIRECTORY)}`);
    expect(r.status).toBe(200);
    const claims = await verifyAccessToken(r.body.token, { audience: DIRECTORY, issuers: [BASE] });
    expect(claims.callsign).toBe(callsign);
    expect(claims.callsign_verified).toBe(false);
    expect(claims.role).toBe("user");
    expect(claims.clubs).toEqual([]);
    await expect(verifyAccessToken(r.body.token, { audience: "http://localhost:8790", issuers: [BASE] })).rejects.toMatchObject({ code: "wrong_audience" });
    expect((await api(`/api/v1/token?aud=https://evil.example`)).status).toBe(400);
  });

  it("creates a club, puts it in the token, and emits signed webhooks", async () => {
    const r = await api("/api/v1/me/clubs", { method: "POST", headers: { "content-type": "application/json" }, body: JSON.stringify({ callsign: clubCall }) });
    expect(r.status).toBe(201);
    const t = await api(`/api/v1/token?aud=${encodeURIComponent(DIRECTORY)}`);
    const claims = await verifyAccessToken(t.body.token, { audience: DIRECTORY, issuers: [BASE] });
    expect(claims.clubs).toEqual([{ id: r.body.id, callsign: clubCall, role: "owner", verified: false }]);
    // The dispatcher runs every 5 s.
    for (let i = 0; i < 40 && !events.some((e) => e.type === "club.created"); i++) await new Promise((res) => setTimeout(res, 250));
    expect(events.find((e) => e.type === "club.created")?.data).toMatchObject({ id: r.body.id, callsign: clubCall, name: clubCall });
    const del = await api(`/api/v1/me/clubs/${r.body.id}`, { method: "DELETE" });
    expect(del.status).toBe(204);
  }, 20_000);

  it("gives service clients a token for the Accounts API (spec §6)", async () => {
    const secret = devClients.OPENRMS_DIRECTORY_CLIENT_SECRET;
    expect(secret, "run pnpm cli seed-clients and keep .dev-clients.env").toBeTruthy();
    const basic = Buffer.from(`openrms-directory:${secret}`).toString("base64");
    const tok = await api("/api/auth/oauth2/token", {
      method: "POST",
      headers: { authorization: `Basic ${basic}`, ...FORM },
      body: new URLSearchParams({ grant_type: "client_credentials", resource: BASE }).toString(),
    });
    expect(tok.status, JSON.stringify(tok.body)).toBe(200);
    const at = tok.body.access_token as string;
    const found = await api(`/api/v1/users?callsign=${callsign}`, { headers: { authorization: `Bearer ${at}` } });
    expect(found.status).toBe(200);
    expect(found.body.users[0]).toMatchObject({ callsign, callsign_verified: false, role: "user", banned: false });
    const one = await api(`/api/v1/users/${found.body.users[0].sub}`, { headers: { authorization: `Bearer ${at}` } });
    expect(one.body.callsign).toBe(callsign);
    // A user's token is not a service token.
    const userTok = await api(`/api/v1/token?aud=${encodeURIComponent(DIRECTORY)}`);
    expect((await api(`/api/v1/users/${found.body.users[0].sub}`, { headers: { authorization: `Bearer ${userTok.body.token}`, cookie: "" } })).status).toBe(401);
  });

  it("links a device with a token bound to the Directory (RFC 8628 + 8707)", async () => {
    const start = await api("/api/auth/device/code", {
      method: "POST",
      ...form({ client_id: "openrms-watch", scope: "openid callsign clubs offline_access", resource: DIRECTORY }),
    });
    expect(start.status, JSON.stringify(start.body)).toBe(200);
    expect(start.body.verification_uri).toBe(`${BASE}/link`);
    const pending = await api("/api/auth/oauth2/token", {
      method: "POST",
      ...form({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: start.body.device_code, client_id: "openrms-watch" }),
    });
    expect(pending.body.error).toBe("authorization_pending");
    // The approval page first claims the code for the signed-in session, then approves it.
    const claim = await api(`/api/auth/device?user_code=${encodeURIComponent(start.body.user_code)}`);
    expect(claim.status, JSON.stringify(claim.body)).toBe(200);
    const approve = await api("/api/auth/device/approve", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ userCode: start.body.user_code }),
    });
    expect(approve.status, JSON.stringify(approve.body)).toBe(200);
    await new Promise((r) => setTimeout(r, (start.body.interval ?? 5) * 1000 + 300)); // honour the polling interval
    const tok = await api("/api/auth/oauth2/token", {
      method: "POST",
      ...form({ grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: start.body.device_code, client_id: "openrms-watch" }),
    });
    expect(tok.status, JSON.stringify(tok.body)).toBe(200);
    const claims = await verifyAccessToken(tok.body.access_token, { audience: DIRECTORY, issuers: [BASE] });
    expect(claims.callsign).toBe(callsign);
    expect(claims.client_id).toBe("openrms-watch");
    expect(claims.role).toBeUndefined(); // third-party / public clients never get the staff role
    expect(tok.body.refresh_token).toBeTruthy();
    deviceRefresh = tok.body.refresh_token;
    const again = await api("/api/auth/oauth2/token", {
      method: "POST",
      ...form({ grant_type: "refresh_token", refresh_token: deviceRefresh, client_id: "openrms-watch", resource: DIRECTORY }),
    });
    expect(again.status, JSON.stringify(again.body)).toBe(200);
    deviceRefresh = again.body.refresh_token ?? deviceRefresh;
  }, 20_000);

  it("refuses cross-origin state changes on cookie routes (CSRF)", async () => {
    const r = await api("/api/v1/me/clubs", {
      method: "POST",
      headers: { origin: "https://evil.example", "content-type": "text/plain" },
      body: JSON.stringify({ callsign: `K9${letters()}` }),
    });
    expect(r.status).toBe(403);
  });

  it("does not emit events for rejected admin calls", async () => {
    const before = (await q(`SELECT count(*)::int AS n FROM event_outbox WHERE type = 'user.banned'`)).rows[0].n;
    const { rows } = await q(`SELECT id FROM "user" WHERE callsign = $1`, [callsign]);
    const r = await fetch(`${BASE}/api/auth/admin/ban-user`, {
      method: "POST",
      headers: { "content-type": "application/json", origin: "http://localhost:5173" },
      body: JSON.stringify({ userId: rows[0].id }),
    });
    expect(r.status).toBe(401);
    expect((await q(`SELECT count(*)::int AS n FROM event_outbox WHERE type = 'user.banned'`)).rows[0].n).toBe(before);
  });

  it("a ban ends the device's refresh token and emits user.banned", async () => {
    const { rows: [staff] } = await q(`SELECT id FROM "user" WHERE role LIKE '%superadmin%' LIMIT 1`);
    expect(staff, "needs a superadmin (pnpm cli set-role CALL superadmin)").toBeTruthy();
    const ctx = await auth.$context;
    const s = await ctx.internalAdapter.createSession(staff.id, false);
    const { rows: [me] } = await q(`SELECT id FROM "user" WHERE callsign = $1`, [callsign]);
    const before = (await q(`SELECT count(*)::int AS n FROM event_outbox WHERE type = 'user.banned' AND data->>'sub' = $1`, [me.id])).rows[0].n;
    const ban = await fetch(`${BASE}/api/auth/admin/ban-user`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${s.token}`, origin: "http://localhost:5173" },
      body: JSON.stringify({ userId: me.id }),
    });
    await q(`DELETE FROM session WHERE token = $1`, [s.token]);
    expect(ban.status, await ban.clone().text()).toBe(200);
    expect((await q(`SELECT count(*)::int AS n FROM event_outbox WHERE type = 'user.banned' AND data->>'sub' = $1`, [me.id])).rows[0].n).toBe(before + 1);
    const r = await api("/api/auth/oauth2/token", {
      method: "POST",
      ...form({ grant_type: "refresh_token", refresh_token: deviceRefresh, client_id: "openrms-watch", resource: DIRECTORY }),
    });
    expect(r.status).toBe(400);
    expect(r.body.error).toBe("invalid_grant");
  });
});
