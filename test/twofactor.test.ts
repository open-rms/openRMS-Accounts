// Second factors and staff enforcement (spec §4b), against its own Accounts started with
// STAFF_2FA_REQUIRED=true on a spare port, sharing the dev database.
//   ACCOUNTS_E2E=1 pnpm test
import { spawn, execFileSync, type ChildProcess } from "node:child_process";
import { createHmac } from "node:crypto";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import { pool, q } from "../src/db/pool.js";

const PORT = 8797;
const BASE = `http://localhost:${PORT}`;
const AUD = "http://localhost:8787";
const run = process.env.ACCOUNTS_E2E ? describe : describe.skip;
const root = new URL("..", import.meta.url).pathname;

const letters = () => Array.from({ length: 3 }, () => String.fromCharCode(65 + Math.floor(Math.random() * 26))).join("");

/** A browser: keeps cookies across calls. */
class Jar {
  cookies = new Map<string, string>();
  async call(path: string, init: { method?: string; json?: unknown } = {}) {
    const headers: Record<string, string> = { origin: BASE };
    if (this.cookies.size) headers.cookie = [...this.cookies].map(([k, v]) => `${k}=${v}`).join("; ");
    if (init.json !== undefined) headers["content-type"] = "application/json";
    const res = await fetch(`${BASE}${path}`, {
      method: init.method ?? (init.json !== undefined ? "POST" : "GET"),
      headers,
      body: init.json !== undefined ? JSON.stringify(init.json) : undefined,
    });
    for (const c of res.headers.getSetCookie()) {
      const [kv] = c.split(";");
      const i = kv!.indexOf("=");
      const name = kv!.slice(0, i), value = kv!.slice(i + 1);
      if (value === "" || /max-age=0/i.test(c)) this.cookies.delete(name);
      else this.cookies.set(name, value);
    }
    const text = await res.text();
    let body: any = text;
    try { body = JSON.parse(text); } catch { /* not JSON */ }
    return { status: res.status, body };
  }
}

function base32(s: string): Buffer {
  const alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
  let bits = "";
  for (const ch of s.replace(/=+$/, "").toUpperCase()) bits += alphabet.indexOf(ch).toString(2).padStart(5, "0");
  const out = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) out.push(parseInt(bits.slice(i, i + 8), 2));
  return Buffer.from(out);
}

/** RFC 6238, SHA-1, 6 digits, 30 s. */
function totp(secret: string, at = Date.now()): string {
  const counter = Buffer.alloc(8);
  counter.writeBigUInt64BE(BigInt(Math.floor(at / 30000)));
  const h = createHmac("sha1", base32(secret)).update(counter).digest();
  const o = h[h.length - 1]! & 0xf;
  return String((h.readUInt32BE(o) & 0x7fffffff) % 1_000_000).padStart(6, "0");
}

async function signUp(jar: Jar, call: string) {
  const r = await jar.call("/api/auth/sign-up/email", {
    json: { email: `${call.toLowerCase()}@example.test`, password: "correct horse battery", name: `Op ${call}`, callsign: call },
  });
  expect(r.status, JSON.stringify(r.body)).toBe(200);
  return r.body.user.id as string;
}

run("second factors and staff (spec §4b)", () => {
  let server: ChildProcess;
  const staffCall = `N8${letters()}`;
  const otherCall = `N7${letters()}`;
  const staff = new Jar();
  let staffId = "", otherId = "", secret = "", backupCodes: string[] = [];

  beforeAll(async () => {
    server = spawn("node", ["--env-file-if-exists=.env", "--import", "tsx", "src/server.ts"], {
      cwd: root,
      env: { ...process.env, PORT: String(PORT), BETTER_AUTH_URL: BASE, UI_URL: BASE, STAFF_2FA_REQUIRED: "true" },
      stdio: ["ignore", "pipe", "pipe"],
    });
    let log = "";
    server.stderr!.on("data", (d) => (log += d));
    for (let i = 0; i < 100; i++) {
      const ok = await fetch(`${BASE}/.well-known/openid-configuration`).then((r) => r.ok, () => false);
      if (ok) return;
      await new Promise((r) => setTimeout(r, 200));
    }
    throw new Error(`test server did not start: ${log}`);
  }, 30_000);

  afterAll(async () => {
    server?.kill();
    await q(`DELETE FROM "user" WHERE callsign = ANY($1)`, [[staffCall, otherCall]]);
    await pool.end();
  });

  it("treats staff without a second factor as user", async () => {
    staffId = await signUp(staff, staffCall);
    await q(`UPDATE "user" SET role = 'admin' WHERE id = $1`, [staffId]);
    const me = await staff.call("/api/v1/me");
    expect(me.body.user.role).toBe("user");
    expect(me.body.staffNeedsSecondFactor).toBe(true);
    const t = await staff.call(`/api/v1/token?aud=${encodeURIComponent(AUD)}`);
    expect(t.status).toBe(200);
    expect(JSON.parse(Buffer.from(t.body.token.split(".")[1], "base64url").toString()).role).toBe("user");
    const adm = await staff.call("/api/v1/admin/me");
    expect(adm.status).toBe(403);
    expect(adm.body.error).toMatch(/2FA/);
    const ba = await staff.call("/api/auth/admin/list-users?limit=1");
    expect(ba.status).toBe(403);
  });

  it("turns on TOTP and gets the staff role back", async () => {
    const en = await staff.call("/api/auth/two-factor/enable", { json: { password: "correct horse battery" } });
    expect(en.status, JSON.stringify(en.body)).toBe(200);
    secret = new URL(en.body.totpURI).searchParams.get("secret")!;
    backupCodes = en.body.backupCodes;
    expect(backupCodes).toHaveLength(10);
    // Not on until the first code checks out.
    expect((await staff.call("/api/v1/me")).body.user.twoFactorEnabled).toBe(false);
    const v = await staff.call("/api/auth/two-factor/verify-totp", { json: { code: totp(secret) } });
    expect(v.status, JSON.stringify(v.body)).toBe(200);
    const me = await staff.call("/api/v1/me");
    expect(me.body.user.twoFactorEnabled).toBe(true);
    expect(me.body.user.role).toBe("admin");
    expect(me.body.staffNeedsSecondFactor).toBe(false);
    expect((await staff.call("/api/v1/admin/me")).status).toBe(200);
    const t = await staff.call(`/api/v1/token?aud=${encodeURIComponent(AUD)}`);
    expect(JSON.parse(Buffer.from(t.body.token.split(".")[1], "base64url").toString()).role).toBe("admin");
    const { rows } = await q(`SELECT 1 FROM audit_log WHERE target = $1 AND action = '2fa.enabled'`, [staffId]);
    expect(rows.length).toBe(1);
  });

  it("asks for the second factor at sign-in; TOTP or a backup code finish it", async () => {
    for (const second of ["totp", "backup"] as const) {
      const jar = new Jar();
      const s = await jar.call("/api/auth/sign-in/email", { json: { email: `${staffCall.toLowerCase()}@example.test`, password: "correct horse battery" } });
      expect(s.status).toBe(200);
      expect(s.body.twoFactorRedirect).toBe(true);
      expect((await jar.call("/api/v1/me")).body.user).toBeNull();
      const v = second === "totp"
        ? await jar.call("/api/auth/two-factor/verify-totp", { json: { code: totp(secret) } })
        : await jar.call("/api/auth/two-factor/verify-backup-code", { json: { code: backupCodes[0] } });
      expect(v.status, JSON.stringify(v.body)).toBe(200);
      expect((await jar.call("/api/v1/me")).body.user.callsign).toBe(staffCall);
    }
    // A backup code works once.
    const jar = new Jar();
    await jar.call("/api/auth/sign-in/email", { json: { email: `${staffCall.toLowerCase()}@example.test`, password: "correct horse battery" } });
    const again = await jar.call("/api/auth/two-factor/verify-backup-code", { json: { code: backupCodes[0] } });
    expect(again.status).not.toBe(200);
  });

  it("won't give a staff role to an account without a second factor", async () => {
    otherId = await signUp(new Jar(), otherCall);
    const ours = await staff.call(`/api/v1/admin/users/${otherId}/role`, { json: { role: "moderator" } });
    expect(ours.status).toBe(403);
    expect(ours.body.error).toMatch(/passkey/);
    const ba = await staff.call("/api/auth/admin/set-role", { json: { userId: otherId, role: "moderator" } });
    expect(ba.status).toBe(403);
    const { rows } = await q<{ role: string | null }>(`SELECT role FROM "user" WHERE id = $1`, [otherId]);
    expect(rows[0]!.role ?? "user").toBe("user");
  });

  it("reset-2fa removes every factor and ends sessions", async () => {
    execFileSync("node", ["--env-file-if-exists=.env", "--import", "tsx", "src/cli.ts", "reset-2fa", staffCall], { cwd: root, stdio: "pipe" });
    const { rows } = await q<{ on: boolean }>(`SELECT "twoFactorEnabled" AS on FROM "user" WHERE id = $1`, [staffId]);
    expect(rows[0]!.on).toBe(false);
    expect((await staff.call("/api/v1/me")).body.user).toBeNull();
    const jar = new Jar();
    const s = await jar.call("/api/auth/sign-in/email", { json: { email: `${staffCall.toLowerCase()}@example.test`, password: "correct horse battery" } });
    expect(s.body.twoFactorRedirect).toBeUndefined();
    expect((await jar.call("/api/v1/me")).body.user.role).toBe("user");
  }, 30_000);
});
