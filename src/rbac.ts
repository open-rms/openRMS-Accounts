// Staff roles for openRMS as a whole, and the rank rule. Moved from openRMS-Directory.
//
//   superadmin  everything, including assigning admins and impersonation
//   admin       users (ban, sessions), assigns moderators
//   moderator   verifies callsigns and clubs
//   user        default
//
// Accounts decides who holds which role and who may assign it. What a role may do inside a
// service (hide a gateway, approve a rig profile) is that service's own permission table,
// keyed on the `role` claim (openRMS-Spec/accounts/identity.md §4).
import { createAccessControl } from "better-auth/plugins/access";
import { defaultStatements } from "better-auth/plugins/admin/access";

export const statements = {
  ...defaultStatements,
  callsign: ["verify"],
  club: ["list", "verify"],
  role: ["assign-moderator", "assign-admin", "assign-superadmin"],
  audit: ["view"],
  client: ["list", "manage"],
} as const;

export const ac = createAccessControl(statements);

const moderatorPerms = {
  user: ["list", "get"],
  session: [],
  callsign: ["verify"],
  club: ["list", "verify"],
  role: [],
  audit: [],
  client: [],
} as const;

export const roles = {
  user: ac.newRole({ user: [], session: [] }),
  moderator: ac.newRole(moderatorPerms),
  admin: ac.newRole({
    ...moderatorPerms,
    user: ["list", "get", "ban", "update"],
    session: ["list", "revoke"],
    role: ["assign-moderator"],
    audit: ["view"],
    client: ["list"],
  }),
  superadmin: ac.newRole({
    user: ["create", "list", "set-role", "ban", "impersonate", "impersonate-admins", "delete", "set-password", "set-email", "get", "update"],
    session: ["list", "revoke", "delete"],
    callsign: ["verify"],
    club: ["list", "verify"],
    role: ["assign-moderator", "assign-admin", "assign-superadmin"],
    audit: ["view"],
    client: ["list", "manage"],
  }),
};

export type RoleName = keyof typeof roles;
export const ROLE_NAMES = Object.keys(roles) as RoleName[];
export const RANK: Record<RoleName, number> = { user: 0, moderator: 1, admin: 2, superadmin: 3 };

export function roleOf(role: string | null | undefined): RoleName {
  // Better Auth allows comma-separated roles; take the strongest one we know.
  const names = (role ?? "user").split(",").map((r) => r.trim()) as RoleName[];
  return names.filter((r) => r in RANK).sort((a, b) => RANK[b] - RANK[a])[0] ?? "user";
}

type Perms = { [K in keyof typeof statements]?: readonly (typeof statements)[K][number][] };

export function can(role: string | null | undefined, perms: Perms): boolean {
  return roles[roleOf(role)].authorize(perms as never).success;
}

/** May `actorRole` act on an account with `targetRole`? Only on accounts ranked below. */
export function outranks(actorRole: string | null | undefined, targetRole: string | null | undefined): boolean {
  return RANK[roleOf(actorRole)] > RANK[roleOf(targetRole)];
}

/** May `actorRole` give someone `newRole`? */
export function canAssign(actorRole: string | null | undefined, newRole: RoleName): boolean {
  const actor = roleOf(actorRole);
  if (newRole === "user") return RANK[actor] >= RANK.admin;
  if (!can(actor, { role: [`assign-${newRole}` as "assign-moderator"] })) return false;
  return actor === "superadmin" || RANK[newRole] < RANK[actor];
}

export function permissionsOf(role: string | null | undefined): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const [res, actions] of Object.entries(statements)) {
    const ok = actions.filter((a) => can(role, { [res]: [a] } as Perms));
    if (ok.length) out[res] = ok;
  }
  return out;
}
