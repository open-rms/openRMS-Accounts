// Profile visibility (openRMS-Spec/accounts/identity.md §4a, §6a). Each field is public (anyone),
// members (anyone signed in to openRMS) or private (the owner and staff tools). The callsign is
// always public. A public grid is cut to 4 characters.
import { z } from "zod";
import { avatarPublicUrl, avatarVersion } from "./avatar.js";
import { q } from "./db/pool.js";

export const FIELDS = ["name", "grid", "city", "bio", "links", "avatar"] as const;
export type Field = (typeof FIELDS)[number];
export const LEVELS = ["public", "members", "private"] as const;
export type Level = (typeof LEVELS)[number];
export type Visibility = Record<Field, Level>;

export const DEFAULT_VISIBILITY: Visibility = { name: "members", grid: "private", city: "private", bio: "public", links: "public", avatar: "public" };

export type Viewer = "public" | "members" | "owner";
const RANK: Record<Level, number> = { public: 0, members: 1, private: 2 };
const VIEW: Record<Viewer, number> = { public: 0, members: 1, owner: 2 };
export const canSee = (level: Level, viewer: Viewer) => VIEW[viewer] >= RANK[level];

export const linkSchema = z.object({
  kind: z.enum(["qrz", "website", "other"]),
  url: z.string().max(200).url().refine((u) => u.startsWith("https://"), "links must start with https://"),
});

export const profileInput = z.object({
  bio: z.string().max(280).nullable().optional(),
  city: z.string().max(64).nullable().optional(),
  links: z.array(linkSchema).max(5).optional(),
  visibility: z.object(Object.fromEntries(FIELDS.map((f) => [f, z.enum(LEVELS).optional()])) as Record<Field, z.ZodOptional<z.ZodEnum<{ public: "public"; members: "members"; private: "private" }>>>).partial().optional(),
  hidden: z.boolean().optional(),
  avatar: z.object({
    source: z.enum(["none", "gravatar", "url"]),
    url: z.string().max(500).url().refine((u) => u.startsWith("https://"), "the picture URL must start with https://").nullable().optional(),
  }).optional(),
});

export interface ProfileRow {
  bio: string | null;
  city: string | null;
  links: { kind: string; url: string }[];
  visibility: Visibility;
  hidden: boolean;
  avatarSource: "none" | "gravatar" | "url";
  avatarUrl: string | null;
}

export async function loadProfile(sub: string): Promise<ProfileRow> {
  const { rows } = await q<{ bio: string | null; city: string | null; links: unknown; visibility: unknown; hidden: boolean; avatar_source: string; avatar_url: string | null }>(
    `SELECT bio, city, links, visibility, hidden, avatar_source, avatar_url FROM profile WHERE sub = $1`,
    [sub],
  );
  const r = rows[0];
  return {
    bio: r?.bio ?? null,
    city: r?.city ?? null,
    links: Array.isArray(r?.links) ? (r!.links as ProfileRow["links"]) : [],
    visibility: { ...DEFAULT_VISIBILITY, ...((r?.visibility ?? {}) as Partial<Visibility>) },
    hidden: !!r?.hidden,
    avatarSource: (r?.avatar_source ?? "none") as ProfileRow["avatarSource"],
    avatarUrl: r?.avatar_url ?? null,
  };
}

/** A grid as a viewer at this level may see it: public is at most 4 characters (e.g. CN87). */
export function gridFor(grid: string | null | undefined, level: Level, viewer: Viewer): string | null {
  if (!grid || !canSee(level, viewer)) return null;
  return level === "public" && viewer === "public" ? grid.slice(0, 4) : grid;
}

/**
 * Profile claims for a third-party token (spec §4a): what a signed-in member could see, so a
 * private field is null and a public grid is cut to 4 characters. First-party tokens skip this.
 */
export async function thirdPartyProfile(sub: string, name: string, grid: string | null, email: string) {
  const p = await loadProfile(sub);
  const picture = pictureFor(sub, p, email);
  return {
    name: canSee(p.visibility.name, "members") ? name : null,
    grid: gridFor(grid, p.visibility.grid, "members"),
    ...(picture ? { picture } : {}),
  };
}

/** The `picture` claim: the proxy URL, only when an avatar is set and public (spec §4). */
export function pictureFor(sub: string, p: ProfileRow, email: string): string | null {
  if (p.avatarSource === "none" || p.visibility.avatar !== "public") return null;
  return avatarPublicUrl(sub, avatarVersion(p.avatarSource, p.avatarUrl, email));
}
