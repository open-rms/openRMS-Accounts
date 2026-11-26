// @openrms/service-auth against a stand-in issuer: verification keeps working when the issuer
// can't be reached (spec §5.5), and RevocationSync's cursor only moves on pulled rows.
import { createServer, type Server } from "node:http";
import { mkdtempSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, beforeAll, beforeEach, describe, expect, it } from "vitest";
import { exportJWK, generateKeyPair, SignJWT, type CryptoKey } from "jose";
import { clearJwksMemory, KEY_PREFIX, KEY_TYP, RevocationSync, verifyAccessToken, verifyBearer, type RevokedKey } from "@openrms/service-auth";

let server: Server;
let issuer = "";
let down = false;
const keys: { kid: string; priv: CryptoKey; jwk: Record<string, unknown> }[] = [];
let revoked: RevokedKey[] = [];
let lastSince = "";
const AUD = "https://atlas.example";

async function addKey(kid: string) {
  const { privateKey, publicKey } = await generateKeyPair("EdDSA", { extractable: true });
  keys.push({ kid, priv: privateKey, jwk: { ...(await exportJWK(publicKey)), kid, alg: "EdDSA" } });
}

const sign = (kid: string, extra: Record<string, unknown> = {}, typ?: string) =>
  new SignJWT({ scope: "openid", ...extra })
    .setProtectedHeader({ alg: "EdDSA", kid, ...(typ ? { typ } : {}) })
    .setIssuer(issuer).setAudience(AUD).setSubject("user-1").setIssuedAt().setExpirationTime("10m")
    .sign(keys.find((k) => k.kid === kid)!.priv);

beforeAll(async () => {
  await addKey("k1");
  server = createServer((req, res) => {
    if (down) return void res.writeHead(503).end();
    const url = new URL(req.url!, issuer);
    const json = (o: unknown) => res.writeHead(200, { "content-type": "application/json" }).end(JSON.stringify(o));
    if (url.pathname === "/.well-known/openid-configuration") return json({ issuer, jwks_uri: `${issuer}/jwks`, token_endpoint: `${issuer}/token` });
    if (url.pathname === "/jwks") return json({ keys: keys.map((k) => k.jwk) });
    if (url.pathname === "/token") return json({ access_token: "svc", expires_in: 900 });
    if (url.pathname === "/api/v1/keys/revoked") {
      lastSince = url.searchParams.get("since") ?? "";
      return json({ revoked: revoked.filter((r) => r.revoked_at >= lastSince) });
    }
    res.writeHead(404).end();
  });
  await new Promise<void>((r) => server.listen(0, "127.0.0.1", r));
  issuer = `http://127.0.0.1:${(server.address() as { port: number }).port}`;
});
afterAll(() => server.close());
beforeEach(() => {
  down = false;
  clearJwksMemory();
});

describe("JWKS when the issuer is unreachable", () => {
  it("keeps verifying with the last good keys after a failed refresh", async () => {
    const t = await sign("k1");
    expect((await verifyAccessToken(t, { audience: AUD, issuers: [issuer] })).sub).toBe("user-1");
    down = true;
    // Keys count as stale at once; the refresh fails; the held set still verifies.
    await new Promise((r) => setTimeout(r, 5));
    expect((await verifyAccessToken(t, { audience: AUD, issuers: [issuer], jwksMaxAgeMs: 1 })).sub).toBe("user-1");
  });

  it("survives a restart with the cache file", async () => {
    const dir = mkdtempSync(join(tmpdir(), "jwks-"));
    const file = join(dir, "jwks.json");
    try {
      const t = await sign("k1");
      await verifyAccessToken(t, { audience: AUD, issuers: [issuer], jwksCacheFile: file });
      clearJwksMemory(); // "restart"
      down = true;
      expect((await verifyAccessToken(t, { audience: AUD, issuers: [issuer], jwksCacheFile: file })).sub).toBe("user-1");
      clearJwksMemory();
      await expect(verifyAccessToken(t, { audience: AUD, issuers: [issuer] })).rejects.toThrow(); // no file: nothing to go on
    } finally {
      rmSync(dir, { recursive: true, force: true });
    }
  });

  it("fetches again for a key it hasn't seen (rotation)", async () => {
    await verifyAccessToken(await sign("k1"), { audience: AUD, issuers: [issuer] });
    await addKey("k2");
    expect((await verifyAccessToken(await sign("k2"), { audience: AUD, issuers: [issuer], jwksCooldownMs: 0 })).sub).toBe("user-1");
    await addKey("k3"); // within the default 30 s cooldown an unknown kid is refused, not refetched
    await expect(verifyAccessToken(await sign("k3"), { audience: AUD, issuers: [issuer] })).rejects.toThrow();
  });

  it("verifies API keys the same way, and refuses them as access tokens", async () => {
    const key = KEY_PREFIX + (await sign("k1", { token_use: "api_key", jti: "j1", scope: "heartbeat" }, KEY_TYP));
    const b = await verifyBearer(key, { audience: AUD, issuers: [issuer], isRevoked: () => false });
    expect(b.kind).toBe("key");
    down = true;
    expect((await verifyBearer(key, { audience: AUD, issuers: [issuer], isRevoked: () => false, jwksMaxAgeMs: 1 })).kind).toBe("key");
    await expect(verifyBearer(key, { audience: AUD, issuers: [issuer], isRevoked: (j) => j === "j1" })).rejects.toMatchObject({ code: "revoked" });
    await expect(verifyAccessToken(key, { audience: AUD, issuers: [issuer] })).rejects.toThrow(/API keys/);
  });
});

describe("RevocationSync cursor", () => {
  it("moves only on pulled rows, never on webhook rows, and saves after storing", async () => {
    const stored: string[] = [];
    let saved: string | null = null;
    const sync = new RevocationSync({
      issuer, clientId: "svc", clientSecret: "x",
      store: async (ks) => { stored.push(...ks.map((k) => k.jti)); },
      cursor: { load: async () => saved, save: async (iso) => { saved = iso; } },
      log: () => {},
    });
    revoked = [{ jti: "a", sub: "u", exp: 9e9, revoked_at: "2026-11-26T10:00:00.000Z" }];
    expect(await sync.pull()).toBe(1);
    expect(saved).toBe("2026-11-26T10:00:00.000Z");
    // A newer revocation arrives by webhook only; the cursor must not jump to it.
    await sync.ingest({ id: "e1", type: "key.revoked", createdAt: "2026-11-26T12:00:00.000Z", data: { jti: "w", sub: "u", exp: 9e9 } });
    expect(saved).toBe("2026-11-26T10:00:00.000Z");
    // One the pull missed in between is still found next time.
    revoked.push({ jti: "b", sub: "u", exp: 9e9, revoked_at: "2026-11-26T11:00:00.000Z" });
    await sync.pull();
    expect(lastSince).toBe("2026-11-26T09:55:00.000Z"); // cursor minus 5 minutes overlap
    expect(stored).toContain("b");
    expect(saved).toBe("2026-11-26T11:00:00.000Z");
  });

  it("fails open: a pull error is logged, start() still resolves", async () => {
    const logs: string[] = [];
    const sync = new RevocationSync({ issuer, clientId: "svc", clientSecret: "x", store: async () => {}, log: (m) => logs.push(m), intervalMs: 3_600_000 });
    down = true;
    await sync.start();
    sync.stop();
    expect(logs[0]).toMatch(/keys keep working/);
  });
});
