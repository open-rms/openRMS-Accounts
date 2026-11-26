// "My radios" (spec §4, §6) against a running Accounts.   ACCOUNTS_E2E=1 pnpm test
import { readFileSync } from "node:fs";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { verifyAccessToken } from "@openrms/service-auth";
import { pool, q } from "../src/db/pool.js";

const BASE = process.env.ACCOUNTS_URL ?? "http://localhost:8789";
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

run("my radios (spec §4, §6)", () => {
  const call = `K6${letters()}`;
  let sub = "", cookie = "";
  const api = async (path: string, init: { method?: string; json?: unknown; form?: Record<string, string>; headers?: Record<string, string>; anon?: boolean } = {}) => {
    const headers: Record<string, string> = { origin: "http://localhost:5173", ...(cookie && !init.anon ? { cookie } : {}), ...(init.headers ?? {}) };
    let body: string | undefined;
    if (init.json !== undefined) { headers["content-type"] = "application/json"; body = JSON.stringify(init.json); }
    else if (init.form) { headers["content-type"] = "application/x-www-form-urlencoded"; body = new URLSearchParams(init.form).toString(); }
    const res = await fetch(`${BASE}${path}`, { method: init.method ?? (body ? "POST" : "GET"), headers, body });
    const text = await res.text();
    let parsed: any = text;
    try { parsed = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, body: parsed, headers: res.headers };
  };

  beforeAll(async () => {
    const r = await api("/api/auth/sign-up/email", { json: { email: `${call.toLowerCase()}@example.test`, password: "correct horse battery", name: "Radios", callsign: call } });
    expect(r.status).toBe(200);
    sub = r.body.user.id;
    cookie = (r.headers.getSetCookie() ?? []).map((c) => c.split(";")[0]).join("; ");
  });
  afterAll(async () => {
    await q(`DELETE FROM "user" WHERE callsign = $1`, [call]);
    await pool.end();
  });

  let ftdx = "", ic = "";
  it("adds radios; the first is primary; a new primary takes over", async () => {
    const a = await api("/api/v1/me/radios", { json: { model: "RIG_MODEL_FTDX10", hamlib_model: 1042, label: "FTDX-10" } });
    expect(a.status, JSON.stringify(a.body)).toBe(201);
    ftdx = a.body.id;
    expect(a.body.radios[0]).toMatchObject({ model: "RIG_MODEL_FTDX10", primary: true });
    const b = await api("/api/v1/me/radios", { json: { model: "RIG_MODEL_IC7300", hamlib_model: 3073, label: "Shack IC-7300", primary: true } });
    ic = b.body.id;
    expect(b.body.radios.map((r: { model: string; primary: boolean }) => [r.model, r.primary])).toEqual([["RIG_MODEL_IC7300", true], ["RIG_MODEL_FTDX10", false]]);
    // Same macro twice is fine (one macro covers several products).
    const c = await api("/api/v1/me/radios", { json: { model: "RIG_MODEL_FT991", label: "FT-991A", hamlib_model: null } });
    expect(c.status).toBe(201);
  });

  it("validates", async () => {
    expect((await api("/api/v1/me/radios", { json: { model: "FTDX10", label: "x" } })).status).toBe(400);
    expect((await api("/api/v1/me/radios", { json: { model: "RIG_MODEL_IC705", label: "" } })).status).toBe(400);
    expect((await api("/api/v1/me/radios", { json: { model: "RIG_MODEL_IC705", label: "x".repeat(41) } })).status).toBe(400);
    expect((await api("/api/v1/me/radios", { json: { model: "RIG_MODEL_IC705", label: "x" }, anon: true })).status).toBe(401);
  });

  it("puts radios in first-party tokens, primary first", async () => {
    const t = await api(`/api/v1/token?aud=${encodeURIComponent(RIGS)}`);
    const claims = await verifyAccessToken(t.body.token, { audience: RIGS, issuers: [BASE] }) as { radios?: string[] };
    expect(claims.radios).toEqual(["RIG_MODEL_IC7300", "RIG_MODEL_FTDX10", "RIG_MODEL_FT991"]);
  });

  it("renames, re-primaries, reorders and deletes (keeping a primary)", async () => {
    let r = await api(`/api/v1/me/radios/${ftdx}`, { method: "PATCH", json: { label: "Home FTDX-10", primary: true } });
    expect(r.body.radios[0]).toMatchObject({ id: ftdx, label: "Home FTDX-10", primary: true });
    const ids = r.body.radios.map((x: { id: string }) => x.id).reverse();
    r = await api("/api/v1/me/radios/order", { method: "PUT", json: { ids } });
    expect(r.body.radios[0].id).toBe(ftdx); // primary still first
    expect((await api(`/api/v1/me/radios/${ftdx}`, { method: "DELETE" })).status).toBe(204);
    const left = (await api("/api/v1/me/radios")).body.radios;
    expect(left.filter((x: { primary: boolean }) => x.primary)).toHaveLength(1);
    expect(left.find((x: { id: string }) => x.id === ic)).toBeTruthy();
  });

  it("serves radios to services (accounts.read)", async () => {
    const basic = Buffer.from(`openrms-rigs:${devClients.OPENRMS_RIGS_CLIENT_SECRET}`).toString("base64");
    const tok = await api("/api/auth/oauth2/token", { headers: { authorization: `Basic ${basic}` }, form: { grant_type: "client_credentials", resource: BASE, scope: "accounts.read" }, anon: true });
    expect(tok.status, JSON.stringify(tok.body)).toBe(200);
    const svc = { authorization: `Bearer ${tok.body.access_token}` };
    const list = await api(`/api/v1/users/${sub}/radios`, { headers: svc, anon: true });
    expect(list.status).toBe(200);
    expect(list.body[0]).toEqual(expect.objectContaining({ model: expect.stringMatching(/^RIG_MODEL_/), label: expect.any(String), primary: true }));
    expect(list.body[0].id).toBeUndefined();
    const user = await api(`/api/v1/users/${sub}`, { headers: svc, anon: true });
    expect(user.body.radios.length).toBe(2);
  });

  it("caps at 20", async () => {
    for (let i = 0; i < 18; i++) await api("/api/v1/me/radios", { json: { model: "RIG_MODEL_DUMMY", label: `r${i}` } });
    expect((await api("/api/v1/me/radios", { json: { model: "RIG_MODEL_DUMMY", label: "too many" } })).status).toBe(409);
  });
});
