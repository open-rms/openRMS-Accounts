// Account export and self-service deletion (spec §4c) against a running Accounts.
//   ACCOUNTS_E2E=1 pnpm test
import { createHash } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { pool, q } from "../src/db/pool.js";

const BASE = process.env.ACCOUNTS_URL ?? "http://localhost:8789";
const run = process.env.ACCOUNTS_E2E ? describe : describe.skip;
const letters = () => Array.from({ length: 3 }, () => String.fromCharCode(65 + Math.floor(Math.random() * 26))).join("");

run("export and self-service deletion (spec §4c)", () => {
  const call = `K4${letters()}`, club = `W4${letters()}`;
  const email = `${call.toLowerCase()}@example.test`, password = "correct horse battery";
  let sub = "", cookie = "";
  const api = async (path: string, init: { method?: string; json?: unknown; anon?: boolean } = {}) => {
    const headers: Record<string, string> = { origin: "http://localhost:5173", ...(cookie && !init.anon ? { cookie } : {}) };
    if (init.json !== undefined) headers["content-type"] = "application/json";
    const res = await fetch(`${BASE}${path}`, { method: init.method ?? (init.json !== undefined ? "POST" : "GET"), headers, body: init.json !== undefined ? JSON.stringify(init.json) : undefined });
    const text = await res.text();
    let body: any = text;
    try { body = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, body, headers: res.headers };
  };
  const signIn = async () => {
    const r = await api("/api/auth/sign-in/email", { json: { email, password }, anon: true });
    expect(r.status).toBe(200);
    cookie = (r.headers.getSetCookie() ?? []).map((c) => c.split(";")[0]).join("; ");
  };

  beforeAll(async () => {
    const r = await api("/api/auth/sign-up/email", { json: { email, password, name: "Leaving", callsign: call }, anon: true });
    expect(r.status).toBe(200);
    sub = r.body.user.id;
    cookie = (r.headers.getSetCookie() ?? []).map((c) => c.split(";")[0]).join("; ");
  });
  afterAll(async () => {
    await q(`DELETE FROM "user" WHERE id = $1`, [sub]);
    await q(`DELETE FROM organization WHERE callsign = $1`, [club]);
    await pool.end();
  });

  it("exports everything Accounts holds as a JSON download", async () => {
    await api("/api/v1/me/radios", { json: { model: "RIG_MODEL_IC7300", label: "IC-7300" } });
    const r = await api("/api/v1/me/account/export");
    expect(r.status).toBe(200);
    expect(r.headers.get("content-disposition")).toContain(`openrms-account-${call}.json`);
    expect(r.body.account).toMatchObject({ id: sub, callsign: call, email });
    expect(r.body.radios[0].model).toBe("RIG_MODEL_IC7300");
    expect(Array.isArray(r.body.sessions) && r.body.sessions.length).toBeTruthy();
    expect(JSON.stringify(r.body)).not.toMatch(/"password"|"secret"|"token"/i);
    expect((await api("/api/v1/me/account/export", { anon: true })).status).toBe(401);
  });

  it("refuses without the right confirmation, password, a fresh sign-in, or while sole club owner", async () => {
    expect((await api("/api/v1/me/account/deletion", { json: { password, confirm: "NOPE" } })).status).toBe(400);
    expect((await api("/api/v1/me/account/deletion", { json: { password: "wrong password!", confirm: call } })).status).toBe(403);
    const created = await api("/api/v1/me/clubs", { json: { callsign: club, name: "Club" } });
    expect(created.status, JSON.stringify(created.body)).toBeLessThan(300);
    const owner = await api("/api/v1/me/account/deletion", { json: { password, confirm: call } });
    expect(owner.status).toBe(409);
    expect(owner.body.clubs).toEqual([club]);
    expect((await api(`/api/v1/me/clubs/${created.body.id}`, { method: "DELETE" })).status).toBeLessThan(300);
    await q(`UPDATE session SET "createdAt" = now() - interval '1 hour' WHERE "userId" = $1`, [sub]);
    const stale = await api("/api/v1/me/account/deletion", { json: { password, confirm: call } });
    expect(stale.status).toBe(403);
    expect(stale.body.reauth).toBe(true);
  });

  it("schedules deletion in 7 days, signs out everywhere, and can be cancelled", async () => {
    await signIn();
    const r = await api("/api/v1/me/account/deletion", { json: { password, confirm: call.toLowerCase() } });
    expect(r.status, JSON.stringify(r.body)).toBe(202);
    const days = (new Date(r.body.deleteAfter).getTime() - Date.now()) / 86400_000;
    expect(days).toBeGreaterThan(6.9);
    expect((await api("/api/v1/me")).body.user).toBeNull();
    await signIn();
    expect((await api("/api/v1/me")).body.pendingDeletion).toBeTruthy();
    expect((await api("/api/v1/me/account/deletion", { method: "DELETE" })).status).toBe(204);
    expect((await api("/api/v1/me")).body.pendingDeletion).toBeNull();
  });

  it("the emailed link cancels without signing in, once", async () => {
    await api("/api/v1/me/account/deletion", { json: { password, confirm: call } });
    const token = "test-cancel-token-" + letters() + "-0123456789";
    await q(`UPDATE account_deletion SET cancel_token_hash = $2 WHERE sub = $1`, [sub, createHash("sha256").update(token).digest("base64url")]);
    expect((await api("/api/v1/deletion/cancel", { json: { token }, anon: true })).status).toBe(200);
    expect((await api("/api/v1/deletion/cancel", { json: { token }, anon: true })).status).toBe(404);
  });

  it("deletes when the grace period is over, telling services", async () => {
    await signIn();
    expect((await api("/api/v1/me/account/deletion", { json: { password, confirm: call } })).status).toBe(202);
    await q(`UPDATE account_deletion SET delete_after = now() - interval '1 minute' WHERE sub = $1`, [sub]);
    const { runDueDeletions } = await import("../src/deletion.js");
    expect(await runDueDeletions()).toBeGreaterThanOrEqual(1);
    expect((await q(`SELECT 1 FROM "user" WHERE id = $1`, [sub])).rowCount).toBe(0);
    const ev = await q(`SELECT 1 FROM event_outbox WHERE type = 'user.deleted' AND data->>'sub' = $1`, [sub]);
    expect(ev.rowCount).toBe(1);
    expect((await q(`SELECT 1 FROM user_radio WHERE sub = $1`, [sub])).rowCount).toBe(0);
  });
});
