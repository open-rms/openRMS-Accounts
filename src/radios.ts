// "My radios" (openRMS-Spec/accounts/identity.md §4, §6). Keys agreed with openRMS-Rigs: the
// Hamlib macro is the stable public key; the Hamlib number is kept as a fallback.
import { z } from "zod";
import { q } from "./db/pool.js";

export const MAX_RADIOS = 20;

export const radioInput = z.object({
  model: z.string().regex(/^RIG_MODEL_[A-Z0-9_]{1,60}$/, "model must be a Hamlib macro, e.g. RIG_MODEL_FTDX10"),
  hamlib_model: z.number().int().min(1).max(999_999).nullable().optional(),
  label: z.string().trim().min(1).max(40),
  primary: z.boolean().optional(),
});

export interface Radio { id: string; model: string; hamlib_model: number | null; label: string; primary: boolean }

/** Primary first, then the user's order. */
export async function radiosOf(sub: string): Promise<Radio[]> {
  const { rows } = await q<{ id: string; model: string; hamlib_model: number | null; label: string; is_primary: boolean }>(
    `SELECT id, model, hamlib_model, label, is_primary FROM user_radio WHERE sub = $1 ORDER BY is_primary DESC, sort_order, created_at`,
    [sub],
  );
  return rows.map((r) => ({ id: r.id, model: r.model, hamlib_model: r.hamlib_model, label: r.label, primary: r.is_primary }));
}

/** The `radios` claim: macros only, primary first, no duplicates, at most 20 (agreed with Rigs). */
export async function radiosClaim(sub: string): Promise<string[]> {
  return [...new Set((await radiosOf(sub)).map((r) => r.model))].slice(0, MAX_RADIOS);
}
