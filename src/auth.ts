// openRMS Accounts: Better Auth as the single sign-on for every openRMS app.
// Contract: openRMS-Spec/accounts/identity.md. Account rules moved here from openRMS-Directory.
import { betterAuth } from "better-auth";
import { APIError, createAuthMiddleware, getSessionFromCtx } from "better-auth/api";
import { admin, bearer, jwt, openAPI, organization } from "better-auth/plugins";
import { oauthDeviceAuthorization, oauthProvider } from "@better-auth/oauth-provider";
import { buildClaims } from "./claims.js";
import { pool } from "./db/pool.js";
import { env } from "./env.js";
import { emit } from "./events.js";
import { isValidBaseCallsign, isValidGrid, normalizeCallsign } from "./lib/callsign.js";
import { sendMail } from "./lib/mail.js";
import { ac, can, canAssign, outranks, roleOf, roles, ROLE_NAMES, type RoleName } from "./rbac.js";

// Registered clients get well-known ids (spec §8, e.g. "openrms-watch"); see registerClient().
let nextClientId: string | undefined;
export async function withClientId<T>(id: string, fn: () => Promise<T>): Promise<T> {
  nextClientId = id;
  try {
    return await fn();
  } finally {
    nextClientId = undefined;
  }
}

// accounts.read: client-credentials scope for the service API (spec §6).
export const SCOPES = ["openid", "profile", "email", "offline_access", "callsign", "clubs", "accounts.read"] as const;

// Admin endpoints that act on another account. Each is also guarded by rank, so an admin
// cannot ban, edit or demote another admin or a superadmin.
const TARGETED = new Set([
  "/admin/set-role", "/admin/update-user", "/admin/ban-user", "/admin/unban-user", "/admin/impersonate-user",
  "/admin/remove-user", "/admin/set-user-password", "/admin/revoke-user-session", "/admin/revoke-user-sessions",
  "/admin/list-user-sessions",
]);

const rankGuard = createAuthMiddleware(async (ctx) => {
  if (!ctx.path.startsWith("/admin/") || ctx.path.startsWith("/admin/oauth2/") || ctx.path === "/admin/has-permission" || ctx.path === "/admin/stop-impersonating") return;
  const session = await getSessionFromCtx(ctx).catch(() => null);
  if (!session) return; // the plugin answers 401 itself
  const actorRole = (session.user as { role?: string }).role;
  const body = (ctx.body ?? {}) as { userId?: string; role?: string | string[]; data?: { role?: string } };
  const requested = body.role ?? body.data?.role;
  if (requested !== undefined) {
    const list = ([] as string[]).concat(requested).flatMap((r) => r.split(",")).map((r) => r.trim());
    for (const r of list) {
      if (!ROLE_NAMES.includes(r as RoleName) || !canAssign(actorRole, r as RoleName)) {
        throw new APIError("FORBIDDEN", { message: `you can't assign the role "${r}"` });
      }
    }
  }
  if (TARGETED.has(ctx.path) && body.userId) {
    if (body.userId === session.user.id && ctx.path !== "/admin/list-user-sessions") {
      throw new APIError("FORBIDDEN", { message: "use your own account settings for your account" });
    }
    const { rows } = await pool.query<{ role: string | null }>(`SELECT role FROM "user" WHERE id = $1`, [body.userId]);
    if (rows[0] && body.userId !== session.user.id && !outranks(actorRole, rows[0].role)) {
      throw new APIError("FORBIDDEN", { message: `you can't act on a ${roleOf(rows[0].role)} account` });
    }
  }
});

// Events for admin actions that change what services must know (spec §7).
/** Refresh tokens are long-lived (30 days, Watch keeps them): end them on ban and password change. */
export async function revokeUserTokens(userId: string) {
  await pool.query(`UPDATE "oauthRefreshToken" SET revoked = now() WHERE "userId" = $1 AND revoked IS NULL`, [userId]);
}

// Only after the endpoint succeeded: a rejected call (no session, outranked) must not emit.
function succeeded(returned: unknown): boolean {
  if (returned === undefined || returned === null) return false;
  if (returned instanceof APIError) return false;
  if (returned instanceof Response) return returned.status >= 200 && returned.status < 300;
  return true;
}

const adminEvents = createAuthMiddleware(async (ctx) => {
  const userId = (ctx.body as { userId?: string } | undefined)?.userId;
  if (!userId || !ctx.path.startsWith("/admin/") || !succeeded(ctx.context.returned)) return;
  if (ctx.path !== "/admin/remove-user") await pool.query(`UPDATE "user" SET "updatedAt" = now() WHERE id = $1`, [userId]);
  if (ctx.path === "/admin/ban-user") {
    await revokeUserTokens(userId);
    await emit("user.banned", { sub: userId });
  }
  else if (ctx.path === "/admin/unban-user") await emit("user.unbanned", { sub: userId });
  else if (ctx.path === "/admin/remove-user") await emit("user.deleted", { sub: userId });
  else if (ctx.path === "/admin/set-role" || ctx.path === "/admin/update-user") await emit("user.updated", { sub: userId });
});

function checkCallsign(raw: unknown): string {
  if (typeof raw !== "string") throw new APIError("BAD_REQUEST", { message: "callsign is required" });
  const call = normalizeCallsign(raw);
  if (!isValidBaseCallsign(call)) {
    throw new APIError("BAD_REQUEST", { message: "callsign must be a bare amateur callsign, e.g. W1AW (no SSID or /P)" });
  }
  return call;
}

/** One holder per callsign, across accounts and clubs. */
async function assertCallsignFree(callsign: string) {
  const { rows } = await pool.query(
    `SELECT 1 FROM "user" WHERE callsign = $1 UNION ALL SELECT 1 FROM organization WHERE callsign = $1`,
    [callsign],
  );
  if (rows.length) throw new APIError("BAD_REQUEST", { message: `an account or club for ${callsign} already exists` });
}

export const auth = betterAuth({
  appName: "openRMS",
  baseURL: env.BETTER_AUTH_URL,
  secret: env.BETTER_AUTH_SECRET,
  basePath: "/api/auth",
  database: pool,
  trustedOrigins: env.trustedOrigins,
  advanced: env.COOKIE_DOMAIN ? { crossSubDomainCookies: { enabled: true, domain: env.COOKIE_DOMAIN } } : {},
  session: { expiresIn: 7 * 24 * 3600, updateAge: 24 * 3600 },
  emailAndPassword: {
    enabled: true,
    minPasswordLength: 10,
    requireEmailVerification: env.REQUIRE_EMAIL_VERIFICATION,
    revokeSessionsOnPasswordReset: true,
    sendResetPassword: async ({ user, url }) => {
      await sendMail(user.email, "Reset your openRMS password", `Reset your password: ${url}`);
    },
  },
  emailVerification: {
    sendOnSignUp: env.REQUIRE_EMAIL_VERIFICATION,
    sendVerificationEmail: async ({ user, url }) => {
      await sendMail(user.email, "Verify your openRMS email", `Verify your email: ${url}`);
    },
  },
  user: {
    additionalFields: {
      // Required at sign-up. One account per callsign (unique index, and checked against clubs).
      callsign: { type: "string", required: true, input: true },
      // Set by a moderator (or a future LoTW / on-air proof flow), never by the user.
      callsignVerified: { type: "boolean", required: false, defaultValue: false, input: false },
      callsignVerifiedMethod: { type: "string", required: false, input: false },
      gridsquare: { type: "string", required: false, input: true },
    },
  },
  databaseHooks: {
    account: {
      update: {
        // A password change or reset ends every app's refresh token (sessions: revokeSessionsOnPasswordReset).
        after: async (account) => {
          if ((account as { password?: string | null }).password) await revokeUserTokens(account.userId);
        },
      },
    },
    user: {
      create: {
        before: async (user) => {
          const callsign = checkCallsign((user as Record<string, unknown>).callsign);
          await assertCallsignFree(callsign);
          const grid = (user as Record<string, unknown>).gridsquare;
          if (grid != null && grid !== "" && !isValidGrid(String(grid))) throw new APIError("BAD_REQUEST", { message: "gridsquare is not a Maidenhead locator" });
          return { data: { ...user, callsign, callsignVerified: false } };
        },
      },
      update: {
        before: async (data) => {
          const d = data as Record<string, unknown>;
          // Services key data on the account id, but gateways and profiles are listed under the
          // callsign, so a self-service change is not allowed. Moderators use `pnpm cli set-callsign`.
          if (d.callsign !== undefined) throw new APIError("BAD_REQUEST", { message: "callsign cannot be changed here; ask a moderator" });
          if (d.gridsquare != null && d.gridsquare !== "" && !isValidGrid(String(d.gridsquare))) {
            throw new APIError("BAD_REQUEST", { message: "gridsquare is not a Maidenhead locator" });
          }
          return { data: d };
        },
        after: async (user) => {
          await emit("user.updated", { sub: user.id });
        },
      },
    },
  },
  hooks: { before: rankGuard, after: adminEvents },
  plugins: [
    // Signing keys and JWKS for every token Accounts issues. The issuer is our origin.
    jwt({
      jwt: { issuer: env.ISSUER, expirationTime: "15m" },
      // Not used by first-party apps (they call /api/v1/token with an audience), but keep the
      // session's JWT header off so tokens with aud=issuer don't leak into service calls.
      disableSettingJwtHeader: true,
    }),
    oauthProvider({
      loginPage: `${env.UI_URL}/login`,
      consentPage: `${env.UI_URL}/consent`,
      scopes: [...SCOPES],
      // Services (Directory, Rigs) plus Accounts itself, for the service API (client credentials).
      resources: [...new Set([...env.resources, env.ISSUER])],
      accessTokenExpiresIn: 15 * 60,
      refreshTokenExpiresIn: 30 * 24 * 3600,
      allowDynamicClientRegistration: false,
      generateClientId: () => nextClientId ?? crypto.randomUUID(),
      // Clients belong to openRMS, not to the staff member who registered them, and only
      // superadmins manage them (third-party registration is admin-approved; spec AC3).
      clientReference: () => "openrms",
      clientPrivileges: ({ user }) => can(user?.role as string | undefined, { client: ["manage"] }),
      customAccessTokenClaims: async ({ user, scopes, metadata }) =>
        user ? buildClaims(user as never, scopes, metadata?.firstParty === true) : {},
      customIdTokenClaims: async ({ user, scopes }) => buildClaims(user as never, scopes, false),
      customUserInfoClaims: async ({ user, scopes }) => buildClaims(user as never, scopes, false),
    }),
    // RFC 8628 for headless apps (openRMS-Watch, later rigctlweb, hamstack). The client must be a
    // registered OAuth client; the token is a real access token bound to the requested resource.
    oauthDeviceAuthorization({ verificationUri: `${env.UI_URL}/link`, expiresIn: "15m", interval: "5s" }),
    bearer(),
    admin({ ac, roles, defaultRole: "user", adminRoles: ["superadmin", "admin", "moderator"] }),
    // Clubs: one organization per extra callsign (club, special-event, or a second personal call).
    organization({
      allowUserToCreateOrganization: true,
      organizationLimit: 20,
      creatorRole: "owner",
      membershipLimit: 200,
      schema: {
        organization: {
          additionalFields: {
            callsign: { type: "string", required: true, input: true },
            callsignVerified: { type: "boolean", required: false, defaultValue: false, input: false },
            callsignVerifiedMethod: { type: "string", required: false, input: false },
          },
        },
      },
      sendInvitationEmail: async ({ email, organization: org, inviter }) => {
        await sendMail(email, `Join ${org.name} on openRMS`, `${inviter.user.name} invited you to manage ${org.name}. Sign in to accept.`);
      },
      organizationHooks: {
        beforeCreateOrganization: async ({ organization: org }) => {
          const callsign = checkCallsign((org as Record<string, unknown>).callsign);
          await assertCallsignFree(callsign);
          return {
            data: { ...org, callsign, slug: callsign.toLowerCase(), name: (org.name || callsign).slice(0, 80), callsignVerified: false },
          };
        },
        afterCreateOrganization: async ({ organization: org, user }) => {
          await emit("club.created", { id: org.id, callsign: (org as Record<string, unknown>).callsign, owner: user.id });
        },
        beforeUpdateOrganization: async ({ organization: org }) => {
          const o = org as Record<string, unknown>;
          if (o.callsign !== undefined) throw new APIError("BAD_REQUEST", { message: "a club's callsign cannot be changed; create a new club" });
          if (o.slug !== undefined) throw new APIError("BAD_REQUEST", { message: "slug follows the callsign" });
          return { data: org };
        },
        afterUpdateOrganization: async ({ organization: org }) => {
          if (org) await emit("club.updated", { id: org.id });
        },
        beforeDeleteOrganization: async ({ organization: org }) => {
          // Members lose the club: mark them changed for reconcile while the rows still exist.
          await pool.query(`UPDATE "user" SET "updatedAt" = now() WHERE id IN (SELECT "userId" FROM member WHERE "organizationId" = $1)`, [org.id]);
        },
        afterDeleteOrganization: async ({ organization: org }) => {
          // Services clean up their own data (the Directory removes the club's listings).
          await emit("club.deleted", { id: org.id, callsign: (org as Record<string, unknown>).callsign, name: org.name });
        },
        afterAddMember: async ({ member, organization: org }) => {
          await emit("club.member_added", { id: org.id, sub: member.userId, role: member.role });
        },
        afterRemoveMember: async ({ member, organization: org }) => {
          await emit("club.member_removed", { id: org.id, sub: member.userId });
        },
        afterUpdateMemberRole: async ({ member, organization: org }) => {
          await emit("club.member_added", { id: org.id, sub: member.userId, role: member.role });
        },
      },
    }),
    openAPI(),
  ],
});

export type Session = typeof auth.$Infer.Session;
