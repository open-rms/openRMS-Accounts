// Avatar proxy (openRMS-Spec/accounts/identity.md §6a). Accounts fetches the picture itself
// (Gravatar, opt-in, or the user's https URL), so browsers never see the email hash and image
// hosts never see viewers. Every picture is checked and re-encoded to WebP at a fixed size.
import { createHash } from "node:crypto";
import { lookup as dnsLookup, type LookupAddress } from "node:dns";
import { mkdir, readFile, rename, writeFile } from "node:fs/promises";
import https from "node:https";
import { BlockList, isIP } from "node:net";
import { join } from "node:path";
import sharp from "sharp";
import { env } from "./env.js";

export const SIZES = [64, 128, 256] as const;
export type Size = (typeof SIZES)[number];
const MAX_BYTES = 2 * 1024 * 1024;
const TIMEOUT_MS = 5000;
const TTL_MS = 24 * 3600_000;
const MISS_TTL_MS = 3600_000;

// ---------------------------------------------------------------- where a picture comes from

export type AvatarSource = "none" | "gravatar" | "url";

export function gravatarUrl(email: string): string {
  const hash = createHash("sha256").update(email.trim().toLowerCase()).digest("hex");
  return `https://gravatar.com/avatar/${hash}?s=256&d=404&r=g`;
}

/** Short tag of the current source, so the public URL changes when the picture does. */
export function avatarVersion(source: AvatarSource, url: string | null, email: string): string {
  const what = source === "gravatar" ? gravatarUrl(email) : source === "url" ? url ?? "" : "";
  return createHash("sha256").update(`${source}|${what}`).digest("base64url").slice(0, 10);
}

export function avatarPublicUrl(sub: string, version: string, size: Size = 128): string {
  return `${env.ISSUER}/api/v1/avatars/${encodeURIComponent(sub)}?s=${size}&v=${version}`;
}

// ---------------------------------------------------------------- SSRF guard

// Never fetch from inside: loopback, private, link-local, CGNAT, unique-local, multicast, reserved.
const blocked = new BlockList();
for (const [net, bits] of [
  ["0.0.0.0", 8], ["10.0.0.0", 8], ["100.64.0.0", 10], ["127.0.0.0", 8], ["169.254.0.0", 16], ["172.16.0.0", 12],
  ["192.0.0.0", 24], ["192.0.2.0", 24], ["192.168.0.0", 16], ["198.18.0.0", 15], ["198.51.100.0", 24], ["203.0.113.0", 24],
  ["224.0.0.0", 4], ["240.0.0.0", 4],
] as const) blocked.addSubnet(net, bits, "ipv4");
for (const [net, bits] of [
  // IPv4-mapped (::ffff:a.b.c.d) is unwrapped and checked as IPv4 below: a ::ffff:0:0/96 rule
  // here would match every IPv4 address, since BlockList compares IPv4 as mapped IPv6.
  ["::", 128], ["::1", 128], ["64:ff9b::", 96], ["100::", 64], ["2001:db8::", 32], ["fc00::", 7], ["fe80::", 10], ["ff00::", 8],
] as const) blocked.addSubnet(net, bits, "ipv6");

export function isBlockedAddress(addr: string): boolean {
  const mapped = /^::ffff:(\d+\.\d+\.\d+\.\d+)$/i.exec(addr);
  if (mapped) return isBlockedAddress(mapped[1]!);
  const family = isIP(addr);
  if (!family) return true;
  return blocked.check(addr, family === 6 ? "ipv6" : "ipv4");
}

/** DNS lookup that refuses internal addresses, used at connect time (no check-then-use gap). */
function safeLookup(hostname: string, options: object, cb: (err: NodeJS.ErrnoException | null, address: string | LookupAddress[], family?: number) => void) {
  dnsLookup(hostname, { ...options, all: true }, (err, addresses) => {
    if (err) return cb(err, []);
    const list = addresses as LookupAddress[];
    const bad = list.find((a) => isBlockedAddress(a.address));
    if (!list.length || bad) return cb(Object.assign(new Error(`refusing to fetch from ${bad?.address ?? hostname}`), { code: "EBLOCKED" }), []);
    if ((options as { all?: boolean }).all) return cb(null, list);
    cb(null, list[0]!.address, list[0]!.family);
  });
}

class FetchError extends Error {}

/** GET an https image: no internal hosts, at most 3 redirects, 2 MB, 5 s. */
export function fetchImage(url: string, redirects = 3): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    let u: URL;
    try {
      u = new URL(url);
    } catch {
      return reject(new FetchError("bad URL"));
    }
    if (u.protocol !== "https:") return reject(new FetchError("https only"));
    if (u.username || u.password) return reject(new FetchError("no credentials in URLs"));
    if (isIP(u.hostname.replace(/^\[|\]$/g, "")) && isBlockedAddress(u.hostname.replace(/^\[|\]$/g, ""))) return reject(new FetchError("internal address"));
    const req = https.get(u, { lookup: safeLookup as never, timeout: TIMEOUT_MS, headers: { "user-agent": "openRMS-Accounts-avatar/1", accept: "image/webp,image/png,image/jpeg,image/gif" } }, (res) => {
      const status = res.statusCode ?? 0;
      if (status >= 300 && status < 400 && res.headers.location) {
        res.resume();
        if (redirects <= 0) return reject(new FetchError("too many redirects"));
        return fetchImage(new URL(res.headers.location, u).href, redirects - 1).then(resolve, reject);
      }
      if (status !== 200) {
        res.resume();
        return reject(new FetchError(`HTTP ${status}`));
      }
      const declared = Number(res.headers["content-length"] ?? 0);
      if (declared > MAX_BYTES) {
        res.destroy();
        return reject(new FetchError("image larger than 2 MB"));
      }
      const chunks: Buffer[] = [];
      let size = 0;
      res.on("data", (c: Buffer) => {
        size += c.length;
        if (size > MAX_BYTES) {
          res.destroy();
          reject(new FetchError("image larger than 2 MB"));
        } else chunks.push(c);
      });
      res.on("end", () => resolve(Buffer.concat(chunks)));
      res.on("error", reject);
    });
    req.on("timeout", () => req.destroy(new FetchError("timed out")));
    req.on("error", reject);
  });
}

// ---------------------------------------------------------------- checking and re-encoding

/** PNG, JPEG, WebP or GIF by magic bytes. Never SVG (scripts) or anything else. */
export function sniff(buf: Buffer): "png" | "jpeg" | "webp" | "gif" | null {
  if (buf.length >= 8 && buf.subarray(0, 8).equals(Buffer.from([0x89, 0x50, 0x4e, 0x47, 0x0d, 0x0a, 0x1a, 0x0a]))) return "png";
  if (buf.length >= 3 && buf[0] === 0xff && buf[1] === 0xd8 && buf[2] === 0xff) return "jpeg";
  if (buf.length >= 12 && buf.toString("ascii", 0, 4) === "RIFF" && buf.toString("ascii", 8, 12) === "WEBP") return "webp";
  if (buf.length >= 6 && /^GIF8[79]a$/.test(buf.toString("ascii", 0, 6))) return "gif";
  return null;
}

/** Square WebP at `size`, first frame only, metadata stripped. */
export async function reencode(buf: Buffer, size: Size): Promise<Buffer> {
  const kind = sniff(buf);
  if (!kind) throw new FetchError("not a PNG, JPEG, WebP or GIF image");
  const img = sharp(buf, { limitInputPixels: 25_000_000, failOn: "error", animated: false });
  const meta = await img.metadata();
  if (!meta.format || !["png", "jpeg", "webp", "gif"].includes(meta.format)) throw new FetchError("unsupported image");
  return img.rotate().resize(size, size, { fit: "cover" }).webp({ quality: 82 }).toBuffer();
}

// ---------------------------------------------------------------- cache

const dir = () => env.AVATAR_CACHE_DIR;
const misses = new Map<string, number>();

/**
 * The avatar for this source at this size: from the disk cache when fresh, else fetched,
 * checked and re-encoded. Returns null when there's nothing to show (no picture, not found,
 * refused); the page then shows a callsign monogram.
 */
export async function avatarImage(source: AvatarSource, url: string | null, email: string, size: Size): Promise<{ body: Buffer; etag: string } | null> {
  if (source === "none") return null;
  const from = source === "gravatar" ? gravatarUrl(email) : url;
  if (!from) return null;
  const key = createHash("sha256").update(`${from}|${size}`).digest("hex");
  const etag = `"${key.slice(0, 20)}"`;
  const file = join(dir(), `${key}.webp`);
  try {
    const [body, stamp] = await Promise.all([readFile(file), readFile(`${file}.at`, "utf8")]);
    if (Date.now() - Number(stamp) < TTL_MS) return { body, etag };
  } catch { /* not cached */ }
  const missedAt = misses.get(key);
  if (missedAt && Date.now() - missedAt < MISS_TTL_MS) return null;
  try {
    const body = await reencode(await fetchImage(from), size);
    await mkdir(dir(), { recursive: true });
    const tmp = `${file}.${process.pid}.tmp`;
    await writeFile(tmp, body);
    await rename(tmp, file);
    await writeFile(`${file}.at`, String(Date.now()));
    misses.delete(key);
    return { body, etag };
  } catch (e) {
    if (!(e instanceof FetchError) && (e as { code?: string }).code !== "EBLOCKED") console.error("[avatar]", (e as Error).message);
    misses.set(key, Date.now());
    if (misses.size > 10_000) misses.clear();
    return null;
  }
}

/** For the settings page: try a URL now and say why it can't be used. */
export async function checkAvatarUrl(url: string): Promise<string | null> {
  try {
    await reencode(await fetchImage(url), 64);
    return null;
  } catch (e) {
    return e instanceof FetchError || (e as { code?: string }).code === "EBLOCKED" ? (e as Error).message : "that image couldn't be read";
  }
}
