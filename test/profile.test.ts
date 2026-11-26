// Profile visibility and the public profile (spec §4a, §6a) against a running Accounts.
//   ACCOUNTS_E2E=1 pnpm test
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { verifyAccessToken } from "@openrms/service-auth";
import { pool, q } from "../src/db/pool.js";

const BASE = process.env.ACCOUNTS_URL ?? "http://localhost:8789";
const ATLAS = "http://localhost:8787";
const RIGS = "http://localhost:8790";
const run = process.env.ACCOUNTS_E2E ? describe : describe.skip;
const letters = () => Array.from({ length: 3 }, () => String.fromCharCode(65 + Math.floor(Math.random() * 26))).join("");
const devClients = (() => {
  try {
    return Object.fromEntries(readFileSync(new URL("../.dev-clients.env", import.meta.url), "utf8").split("\n").filter((l) => l.includes("=") && !l.startsWith("#")).map((l) => l.split("=", 2) as [string, string]));
  } catch {
    return {} as Record<string, string>;
  }
})();

async function api(path: string, init: { method?: string; json?: unknown; form?: Record<string, string>; cookie?: string; headers?: Record<string, string> } = {}) {
  const headers: Record<string, string> = { origin: "http://localhost:5173", ...(init.cookie ? { cookie: init.cookie } : {}), ...(init.headers ?? {}) };
  let body: string | undefined;
  if (init.json !== undefined) { headers["content-type"] = "application/json"; body = JSON.stringify(init.json); }
  else if (init.form) { headers["content-type"] = "application/x-www-form-urlencoded"; body = new URLSearchParams(init.form).toString(); }
  const res = await fetch(`${BASE}${path}`, { method: init.method ?? (body ? "POST" : "GET"), headers, body });
  const text = await res.text();
  let parsed: any = text;
  try { parsed = JSON.parse(text); } catch { /* not JSON */ }
  return { status: res.status, body: parsed, headers: res.headers };
}

async function signUp(call: string, grid?: string) {
  const r = await api("/api/auth/sign-up/email", {
    json: { email: `${call.toLowerCase()}@example.test`, password: "correct horse battery", name: `Op ${call}`, callsign: call, ...(grid ? { gridsquare: grid } : {}) },
  });
  expect(r.status, JSON.stringify(r.body)).toBe(200);
  return { sub: r.body.user.id as string, cookie: (r.headers.getSetCookie() ?? []).map((c) => c.split(";")[0]).join("; ") };
}

run("profiles and visibility (spec §4a, §6a)", () => {
  const aCall = `N2${letters()}`, bCall = `N1${letters()}`;
  let a: { sub: string; cookie: string }, b: { sub: string; cookie: string };
  const anon = (path: string) => api(path, { headers: { origin: "https://example.org" } });

  beforeAll(async () => {
    a = await signUp(aCall, "CN87uo");
    b = await signUp(bCall);
  });
  afterAll(async () => {
    await q(`DELETE FROM "user" WHERE callsign = ANY($1)`, [[aCall, bCall]]);
    await pool.end();
  });

  it("defaults: strangers see only the callsign; members see the name; the owner sees all", async () => {
    const pub = await anon(`/api/v1/profiles/${aCall}`);
    expect(pub.status).toBe(200);
    expect(pub.body).toEqual({ sub: a.sub, callsign: aCall, callsign_verified: false });
    expect(pub.headers.get("access-control-allow-origin")).toBe("*");
    const mem = await api(`/api/v1/profiles/${aCall.toLowerCase()}`, { cookie: b.cookie });
    expect(mem.body.name).toBe(`Op ${aCall}`);
    expect(mem.body.grid).toBeUndefined();
    expect(mem.headers.get("access-control-allow-origin")).toBe("http://localhost:5173");
    const own = await api(`/api/v1/profiles/${a.sub}`, { cookie: a.cookie });
    expect(own.body).toMatchObject({ self: true, grid: "CN87uo", visibility: { name: "members", grid: "private", city: "private" } });
  });

  it("honours per-field visibility; a public grid shows 4 characters", async () => {
    const put = await api("/api/v1/me/profile", {
      method: "PUT", cookie: a.cookie,
      json: { bio: "QRV on 40m", city: "Moscow, ID", links: [{ kind: "qrz", url: "https://www.qrz.com/db/" + aCall }], visibility: { grid: "public", city: "members", name: "public" } },
    });
    expect(put.status, JSON.stringify(put.body)).toBe(200);
    const pub = await anon(`/api/v1/profiles/${aCall}`);
    expect(pub.body).toMatchObject({ name: `Op ${aCall}`, grid: "CN87", bio: "QRV on 40m", links: [{ kind: "qrz" }] });
    expect(pub.body.city).toBeUndefined();
    const mem = await api(`/api/v1/profiles/${aCall}`, { cookie: b.cookie });
    expect(mem.body).toMatchObject({ grid: "CN87uo", city: "Moscow, ID" });
    // A first-party bearer token counts as signed in too.
    const t = await api(`/api/v1/token?aud=${encodeURIComponent(ATLAS)}`, { cookie: b.cookie });
    const viaToken = await api(`/api/v1/profiles/${aCall}`, { headers: { authorization: `Bearer ${t.body.token}`, origin: "https://example.org" } });
    expect(viaToken.body.city).toBe("Moscow, ID");
    // The owner can preview the public view.
    const preview = await api(`/api/v1/profiles/${aCall}?as=public`, { cookie: a.cookie });
    expect(preview.body.city).toBeUndefined();
    expect(preview.body.self).toBeUndefined();
  });

  it("validates input", async () => {
    expect((await api("/api/v1/me/profile", { method: "PUT", cookie: a.cookie, json: { links: [{ kind: "website", url: "http://insecure.example" }] } })).status).toBe(400);
    expect((await api("/api/v1/me/profile", { method: "PUT", cookie: a.cookie, json: { bio: "x".repeat(281) } })).status).toBe(400);
    expect((await api("/api/v1/me/profile", { method: "PUT", cookie: a.cookie, json: { visibility: { grid: "everyone" } } })).status).toBe(400);
    expect((await api("/api/v1/me/profile", { method: "PUT", json: { bio: "no session" } })).status).toBe(401);
  });

  it("a hidden profile is 404 to everyone but its owner", async () => {
    await api("/api/v1/me/profile", { method: "PUT", cookie: a.cookie, json: { hidden: true } });
    expect((await anon(`/api/v1/profiles/${aCall}`)).status).toBe(404);
    expect((await api(`/api/v1/profiles/${aCall}`, { cookie: b.cookie })).status).toBe(404);
    expect((await api(`/api/v1/profiles/${aCall}`, { cookie: a.cookie })).body.hidden).toBe(true);
    await api("/api/v1/me/profile", { method: "PUT", cookie: a.cookie, json: { hidden: false } });
    expect((await anon(`/api/v1/profiles/${aCall}`)).status).toBe(200);
    expect((await anon(`/api/v1/profiles/NOSUCH9`)).status).toBe(404);
  });

  it("the service API carries the visibility object", async () => {
    const basic = Buffer.from(`openrms-atlas:${devClients.OPENRMS_ATLAS_CLIENT_SECRET}`).toString("base64");
    const tok = await api("/api/auth/oauth2/token", { headers: { authorization: `Basic ${basic}` }, form: { grant_type: "client_credentials", resource: BASE, scope: "accounts.read" } });
    const u = await api(`/api/v1/users/${a.sub}`, { headers: { authorization: `Bearer ${tok.body.access_token}` } });
    expect(u.body).toMatchObject({ grid: "CN87uo", visibility: { name: "public", grid: "public", city: "members", hidden: false } });
  });

  it("third-party tokens get the profile as a member sees it (private fields null)", async () => {
    await api("/api/v1/me/profile", { method: "PUT", cookie: a.cookie, json: { visibility: { name: "private", grid: "private" } } });
    const start = await api("/api/auth/device/code", { form: { client_id: "rigctlweb", scope: "openid profile", resource: RIGS } });
    expect(start.status, JSON.stringify(start.body)).toBe(200);
    expect((await api(`/api/auth/device?user_code=${encodeURIComponent(start.body.user_code)}`, { cookie: a.cookie })).status).toBe(200);
    expect((await api("/api/auth/device/approve", { cookie: a.cookie, json: { userCode: start.body.user_code } })).status).toBe(200);
    await new Promise((r) => setTimeout(r, (start.body.interval ?? 5) * 1000 + 300));
    const tok = await api("/api/auth/oauth2/token", { form: { grant_type: "urn:ietf:params:oauth:grant-type:device_code", device_code: start.body.device_code, client_id: "rigctlweb" } });
    expect(tok.status, JSON.stringify(tok.body)).toBe(200);
    const claims = await verifyAccessToken(tok.body.access_token, { audience: RIGS, issuers: [BASE] });
    expect(claims.name).toBeNull();
    expect(claims.grid).toBeNull();
    // First-party tokens keep full values for server-side use.
    const fp = await api(`/api/v1/token?aud=${encodeURIComponent(ATLAS)}`, { cookie: a.cookie });
    const fpc = await verifyAccessToken(fp.body.token, { audience: ATLAS, issuers: [BASE] });
    expect(fpc).toMatchObject({ name: `Op ${aCall}`, grid: "CN87uo" });
  }, 20_000);
});
