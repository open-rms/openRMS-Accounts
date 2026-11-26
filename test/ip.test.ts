// Client IP for rate limits: TRUSTED_IP_HEADERS feeds Better Auth's advanced.ipAddress.
import { describe, expect, it, vi } from "vitest";
import { getIP } from "better-auth/api";

async function authWith(envs: Record<string, string>) {
  vi.resetModules();
  for (const k of ["TRUSTED_IP_HEADERS", "TRUSTED_PROXIES"]) delete process.env[k];
  Object.assign(process.env, envs, { NODE_ENV: "production", BETTER_AUTH_SECRET: "x".repeat(40) });
  const { auth } = await import("../src/auth.js");
  return auth.options;
}

describe("TRUSTED_IP_HEADERS", () => {
  it("is passed to Better Auth and used to resolve the client IP", async () => {
    const opts = await authWith({ TRUSTED_IP_HEADERS: "CF-Connecting-IP" });
    expect(opts.advanced?.ipAddress?.ipAddressHeaders).toEqual(["cf-connecting-ip"]);
    const ip = getIP(new Headers({ "cf-connecting-ip": "203.0.113.7", "x-forwarded-for": "198.51.100.1" }), opts);
    expect(ip).toBe("203.0.113.7");
  });

  it("leaves Better Auth's default alone when unset", async () => {
    const opts = await authWith({});
    expect(opts.advanced?.ipAddress).toBeUndefined();
    // Default header is x-forwarded-for; a spoofed cf-connecting-ip is ignored.
    expect(getIP(new Headers({ "cf-connecting-ip": "203.0.113.7" }), opts)).not.toBe("203.0.113.7");
  });

  it("passes trusted proxies for forwarded chains", async () => {
    const opts = await authWith({ TRUSTED_IP_HEADERS: "x-forwarded-for", TRUSTED_PROXIES: "127.0.0.1" });
    expect(getIP(new Headers({ "x-forwarded-for": "203.0.113.9, 127.0.0.1" }), opts)).toBe("203.0.113.9");
  });
});
