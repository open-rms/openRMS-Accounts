// Staff need a second factor (openRMS-Spec/accounts/identity.md §4b). With STAFF_2FA_REQUIRED on,
// a staff account without TOTP or a passkey is treated as a plain user everywhere a role is read:
// first-party tokens, the staff API, Better Auth's admin endpoints and the service API.
// The flag exists so a deploy can ship 2FA first, let staff enrol, then turn enforcement on.
import { q } from "./db/pool.js";
import { env } from "./env.js";
import { RANK, roleOf, type RoleName } from "./rbac.js";

export const isStaff = (role: string | null | undefined) => RANK[roleOf(role)] > RANK.user;

/** TOTP enrolled, or at least one passkey. */
export async function hasSecondFactor(userId: string): Promise<boolean> {
  const { rows } = await q<{ ok: boolean }>(
    `SELECT COALESCE((SELECT "twoFactorEnabled" FROM "user" WHERE id = $1), false)
         OR EXISTS (SELECT 1 FROM passkey WHERE "userId" = $1) AS ok`,
    [userId],
  );
  return !!rows[0]?.ok;
}

/** True when this account holds a staff role it may not use yet. */
export async function staffNeedsSecondFactor(userId: string, role: string | null | undefined): Promise<boolean> {
  return env.STAFF_2FA_REQUIRED && isStaff(role) && !(await hasSecondFactor(userId));
}

/** The role this account may act with right now. */
export async function effectiveRole(userId: string, role: string | null | undefined): Promise<RoleName> {
  return (await staffNeedsSecondFactor(userId, role)) ? "user" : roleOf(role);
}

/** Refuse giving a staff role to someone who has no second factor (only while enforcement is on). */
export async function assertCanHoldRole(userId: string, role: RoleName): Promise<string | null> {
  if (!env.STAFF_2FA_REQUIRED || role === "user") return null;
  return (await hasSecondFactor(userId)) ? null : `turn on two-factor sign-in or add a passkey before becoming ${role}`;
}

export const STAFF_2FA_MESSAGE = "staff actions need 2FA: turn on two-factor sign-in or add a passkey in your account settings";
