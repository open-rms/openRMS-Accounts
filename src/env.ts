import { z } from "zod";

const list = (s: string) => s.split(",").map((x) => x.trim()).filter(Boolean);

const schema = z.object({
  DATABASE_URL: z.string().default("postgres://openrms:openrms@127.0.0.1:5442/openrms_accounts"),
  PORT: z.coerce.number().default(8789),
  /** Public origin of Accounts. Also the OIDC issuer (spec §1). */
  BETTER_AUTH_URL: z.string().default("http://localhost:8789"),
  BETTER_AUTH_SECRET: z.string().min(32).optional(),
  /** Parent domain for the shared session cookie, e.g. ".openrms.dev". Unset: host-only cookie (dev). */
  COOKIE_DOMAIN: z.string().optional(),
  /** Comma-separated first-party web origins (Site, Rigs UI, ...). */
  TRUSTED_ORIGINS: z.string().default("http://localhost:5173,http://localhost:5174"),
  /** Where the account pages live (sign-in, consent, device link). Default: Accounts itself (ui/). */
  UI_URL: z.string().optional(),
  /** First-party apps by origin, for "continue to ..." and safe redirects: "origin|Name,origin|Name". */
  APPS: z.string().default("http://localhost:5173|openRMS Directory,http://localhost:5174|openRMS Rigs,https://openrms.dev|openRMS Directory,https://rigs.openrms.dev|openRMS Rigs"),
  /** Comma-separated audiences first-party apps may request from /api/v1/token (spec §3a). */
  FIRST_PARTY_AUDIENCES: z.string().default("http://localhost:8787,http://localhost:8790,https://directory.openrms.dev,https://rigs.openrms.dev"),
  /** Comma-separated resource servers (audiences) OAuth clients may request (RFC 8707). */
  RESOURCES: z.string().default("http://localhost:8787,http://localhost:8790,https://directory.openrms.dev,https://rigs.openrms.dev"),
  REQUIRE_EMAIL_VERIFICATION: z.stringbool().default(false),
  SMTP_URL: z.string().optional(),
  MAIL_FROM: z.string().default("openRMS Accounts <noreply@localhost>"),
});

const parsed = schema.parse(process.env);
const ISSUER = parsed.BETTER_AUTH_URL.replace(/\/+$/, "");
const trustedOrigins = list(parsed.TRUSTED_ORIGINS);
const names = new Map(list(parsed.APPS).map((a) => a.split("|", 2) as [string, string]));
export const env = {
  ...parsed,
  ISSUER,
  UI_URL: (parsed.UI_URL ?? ISSUER).replace(/\/+$/, ""),
  /** Trusted first-party apps a sign-in may return to. */
  apps: trustedOrigins.map((origin) => ({ origin, name: names.get(origin) ?? origin })),
  trustedOrigins,
  firstPartyAudiences: list(parsed.FIRST_PARTY_AUDIENCES),
  resources: list(parsed.RESOURCES),
};
export type Env = typeof env;
