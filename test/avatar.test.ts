// Avatar proxy (spec §6a): SSRF guard and image checks (unit), and visibility end to end
// (ACCOUNTS_E2E=1, against pnpm dev; the picture is put in the cache so nothing is fetched).
import { createHash } from "node:crypto";
import { mkdirSync, writeFileSync } from "node:fs";
import { join } from "node:path";
import { afterAll, beforeAll, describe, expect, it } from "vitest";
import sharp from "sharp";
import { fetchImage, gravatarUrl, isBlockedAddress, reencode, sniff } from "../src/avatar.js";

describe("avatar safety", () => {
  it("blocks internal addresses", () => {
    for (const a of ["127.0.0.1", "10.1.2.3", "172.20.0.1", "192.168.1.1", "169.254.169.254", "100.64.0.1", "0.0.0.0", "::1", "fe80::1", "fd00::1", "::ffff:127.0.0.1", "not-an-ip"]) {
      expect(isBlockedAddress(a), a).toBe(true);
    }
    for (const a of ["1.1.1.1", "8.8.8.8", "2606:4700:4700::1111"]) expect(isBlockedAddress(a), a).toBe(false);
  });

  it("refuses non-https, internal hosts and names that resolve inside", async () => {
    await expect(fetchImage("http://example.com/a.png")).rejects.toThrow(/https only/);
    await expect(fetchImage("https://127.0.0.1/a.png")).rejects.toThrow(/internal/);
    await expect(fetchImage("https://[::1]/a.png")).rejects.toThrow(/internal/);
    await expect(fetchImage("https://localhost/a.png")).rejects.toThrow(/refusing/);
    await expect(fetchImage("https://user:pw@example.com/a.png")).rejects.toThrow(/credentials/);
  });

  it("accepts PNG/JPEG/WebP/GIF by magic bytes, never SVG, and re-encodes to a square WebP", async () => {
    const png = await sharp({ create: { width: 300, height: 200, channels: 3, background: "#0a5" } }).png().toBuffer();
    expect(sniff(png)).toBe("png");
    expect(sniff(Buffer.from('<svg xmlns="http://www.w3.org/2000/svg"><script>alert(1)</script></svg>'))).toBeNull();
    const out = await reencode(png, 64);
    expect(sniff(out)).toBe("webp");
    const meta = await sharp(out).metadata();
    expect([meta.width, meta.height]).toEqual([64, 64]);
    await expect(reencode(Buffer.from("<svg/>"), 64)).rejects.toThrow(/not a PNG/);
  });
});

const BASE = process.env.ACCOUNTS_URL ?? "http://localhost:8789";
const ATLAS = "http://localhost:8787";
const run = process.env.ACCOUNTS_E2E ? describe : describe.skip;
const letters = () => Array.from({ length: 3 }, () => String.fromCharCode(65 + Math.floor(Math.random() * 26))).join("");

run("avatar endpoint (e2e)", () => {
  const call = `K8${letters()}`, other = `K7${letters()}`;
  const email = `${call.toLowerCase()}@example.test`;
  let sub = "", cookie = "", otherCookie = "";
  const api = async (path: string, init: { method?: string; json?: unknown; cookie?: string; headers?: Record<string, string> } = {}) => {
    const headers: Record<string, string> = { origin: "http://localhost:5173", ...(init.cookie ? { cookie: init.cookie } : {}), ...(init.headers ?? {}) };
    if (init.json !== undefined) headers["content-type"] = "application/json";
    const res = await fetch(`${BASE}${path}`, { method: init.method ?? (init.json !== undefined ? "POST" : "GET"), headers, body: init.json !== undefined ? JSON.stringify(init.json) : undefined });
    const buf = Buffer.from(await res.arrayBuffer());
    let body: any = buf;
    try { body = JSON.parse(buf.toString()); } catch { /* binary */ }
    return { status: res.status, body, headers: res.headers };
  };
  const signUp = async (c: string) => {
    const r = await api("/api/auth/sign-up/email", { json: { email: `${c.toLowerCase()}@example.test`, password: "correct horse battery", name: `Op ${c}`, callsign: c } });
    expect(r.status).toBe(200);
    return { id: r.body.user.id as string, cookie: (r.headers.getSetCookie() ?? []).map((x) => x.split(";")[0]).join("; ") };
  };

  beforeAll(async () => {
    const a = await signUp(call);
    sub = a.id;
    cookie = a.cookie;
    otherCookie = (await signUp(other)).cookie;
    // Put the Gravatar picture straight into the dev server's cache (AVATAR_CACHE_DIR default).
    const dir = join(new URL("..", import.meta.url).pathname, ".cache/avatars");
    mkdirSync(dir, { recursive: true });
    const img = await sharp({ create: { width: 128, height: 128, channels: 3, background: "#36c" } }).webp().toBuffer();
    for (const size of [64, 128, 256]) {
      const key = createHash("sha256").update(`${gravatarUrl(email)}|${size}`).digest("hex");
      writeFileSync(join(dir, `${key}.webp`), img);
      writeFileSync(join(dir, `${key}.webp.at`), String(Date.now()));
    }
  });
  afterAll(async () => {
    const { pool, q } = await import("../src/db/pool.js");
    await q(`DELETE FROM "user" WHERE callsign = ANY($1)`, [[call, other]]);
    await pool.end();
  });

  it("refuses a picture URL that points inside", async () => {
    const r = await api("/api/v1/me/profile", { method: "PUT", cookie, json: { avatar: { source: "url", url: "https://localhost/me.png" } } });
    expect(r.status).toBe(400);
    expect(r.body.error).toMatch(/can't use that picture/);
  });

  it("serves a public avatar as WebP with an ETag, in profiles and the picture claim", async () => {
    expect((await api(`/api/v1/avatars/${sub}`)).status).toBe(404); // none yet
    const put = await api("/api/v1/me/profile", { method: "PUT", cookie, json: { avatar: { source: "gravatar" } } });
    expect(put.status, JSON.stringify(put.body)).toBe(200);
    const me = await api("/api/v1/me/profile", { cookie });
    expect(me.body.avatarPreview).toMatch(new RegExp(`/api/v1/avatars/${sub}\\?s=128&v=`));
    const img = await api(`/api/v1/avatars/${sub}?s=64`);
    expect(img.status).toBe(200);
    expect(img.headers.get("content-type")).toBe("image/webp");
    expect(img.headers.get("cache-control")).toMatch(/public/);
    const again = await api(`/api/v1/avatars/${sub}?s=64`, { headers: { "if-none-match": img.headers.get("etag")! } });
    expect(again.status).toBe(304);
    const pub = await api(`/api/v1/profiles/${call}`, { headers: { origin: "https://example.org" } });
    expect(pub.body.picture).toBe(me.body.avatarPreview);
    const t = await api(`/api/v1/token?aud=${encodeURIComponent(ATLAS)}`, { cookie });
    expect(JSON.parse(Buffer.from(t.body.token.split(".")[1], "base64url").toString()).picture).toBe(me.body.avatarPreview);
    // The email hash never reaches a browser.
    expect(JSON.stringify([me.body, pub.body])).not.toContain(createHash("sha256").update(email).digest("hex"));
  });

  it("honours avatar visibility", async () => {
    await api("/api/v1/me/profile", { method: "PUT", cookie, json: { visibility: { avatar: "members" } } });
    expect((await api(`/api/v1/avatars/${sub}`)).status).toBe(404);
    const mem = await api(`/api/v1/avatars/${sub}`, { cookie: otherCookie });
    expect(mem.status).toBe(200);
    expect(mem.headers.get("cache-control")).toMatch(/private/);
    const t = await api(`/api/v1/token?aud=${encodeURIComponent(ATLAS)}`, { cookie });
    expect(JSON.parse(Buffer.from(t.body.token.split(".")[1], "base64url").toString()).picture).toBeUndefined();
    await api("/api/v1/me/profile", { method: "PUT", cookie, json: { visibility: { avatar: "private" } } });
    expect((await api(`/api/v1/avatars/${sub}`, { cookie: otherCookie })).status).toBe(404);
    expect((await api(`/api/v1/avatars/${sub}`, { cookie })).status).toBe(200);
    await api("/api/v1/me/profile", { method: "PUT", cookie, json: { avatar: { source: "none" } } });
    expect((await api(`/api/v1/avatars/${sub}`, { cookie })).status).toBe(404);
  });
});
