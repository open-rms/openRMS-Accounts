// The claims Accounts puts in tokens (openRMS-Spec/accounts/identity.md §4).
import { q } from "./db/pool.js";
import { effectiveRole } from "./staff.js";

export interface UserRow {
  id: string;
  name: string;
  email: string;
  emailVerified: boolean;
  callsign: string;
  callsignVerified: boolean | null;
  callsignVerifiedMethod: string | null;
  gridsquare: string | null;
  role: string | null;
  banned: boolean | null;
}

export const strongestClubRole = (role: string) => (role.includes("owner") ? "owner" : role.includes("admin") ? "admin" : "member") as "owner" | "admin" | "member";

export async function loadUser(id: string): Promise<UserRow | null> {
  const { rows } = await q<UserRow>(
    `SELECT id, name, email, "emailVerified", callsign, "callsignVerified", "callsignVerifiedMethod", gridsquare, role, banned FROM "user" WHERE id = $1`,
    [id],
  );
  return rows[0] ?? null;
}

export async function clubsOf(userId: string) {
  const { rows } = await q<{ id: string; callsign: string; role: string; verified: boolean | null }>(
    `SELECT o.id, o.callsign, m.role, o."callsignVerified" AS verified
       FROM member m JOIN organization o ON o.id = m."organizationId" WHERE m."userId" = $1 ORDER BY o.callsign`,
    [userId],
  );
  return rows.map((r) => ({ id: r.id, callsign: r.callsign, role: strongestClubRole(r.role), verified: !!r.verified }));
}

/**
 * Claims for a user and a set of scopes. `firstParty` adds the staff `role`.
 * `sub`, `iss`, `aud`, `exp` are set by whoever signs the token.
 */
export async function buildClaims(user: Pick<UserRow, "id"> & Partial<UserRow>, scopes: readonly string[], firstParty: boolean) {
  const u = user.callsign === undefined ? await loadUser(user.id) : (user as UserRow);
  if (!u) return {};
  const has = (s: string) => scopes.includes(s);
  const out: Record<string, unknown> = {};
  if (has("profile")) Object.assign(out, { name: u.name, grid: u.gridsquare ?? null });
  if (has("email")) Object.assign(out, { email: u.email, email_verified: !!u.emailVerified });
  if (has("callsign")) {
    Object.assign(out, { callsign: u.callsign, callsign_verified: !!u.callsignVerified, callsign_verified_method: u.callsignVerifiedMethod ?? null });
  }
  if (has("clubs")) out.clubs = await clubsOf(u.id);
  if (firstParty) out.role = await effectiveRole(u.id, u.role);
  return out;
}

/** Scopes that every first-party token carries. */
export const FIRST_PARTY_SCOPES = ["openid", "profile", "email", "callsign", "clubs"] as const;
