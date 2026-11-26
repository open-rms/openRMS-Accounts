// The signed-in user's radios: /api/v1/me/radios (cookie). Every change bumps the account and
// emits user.updated, so services' caches and tokens catch up (spec §4, §7).
import { Hono } from "hono";
import { z } from "zod";
import { q, tx } from "../db/pool.js";
import { emit } from "../events.js";
import { MAX_RADIOS, radioInput, radiosOf } from "../radios.js";
import { requireSession, type SessionVars } from "./session.js";

export const meRadioRoutes = new Hono<SessionVars>();
meRadioRoutes.use("*", requireSession);

const changed = (sub: string) => emit("user.updated", { sub });

meRadioRoutes.get("/", async (c) => c.json({ radios: await radiosOf(c.get("session").user.id), max: MAX_RADIOS }));

meRadioRoutes.post("/", async (c) => {
  const sub = c.get("session").user.id;
  const body = radioInput.safeParse(await c.req.json().catch(() => null));
  if (!body.success) return c.json({ error: body.error.issues[0]?.message ?? "bad request" }, 400);
  const r = body.data;
  const created = await tx(async (t) => {
    const { rows } = await t.query<{ n: number; first: boolean }>(`SELECT count(*)::int AS n, count(*) = 0 AS first FROM user_radio WHERE sub = $1`, [sub]);
    if (rows[0]!.n >= MAX_RADIOS) return null;
    const primary = r.primary || rows[0]!.first;
    if (primary) await t.query(`UPDATE user_radio SET is_primary = false WHERE sub = $1`, [sub]);
    const ins = await t.query<{ id: string }>(
      `INSERT INTO user_radio (sub, model, hamlib_model, label, is_primary, sort_order) VALUES ($1, $2, $3, $4, $5, $6) RETURNING id`,
      [sub, r.model, r.hamlib_model ?? null, r.label, primary, rows[0]!.n],
    );
    return ins.rows[0]!.id;
  });
  if (!created) return c.json({ error: `at most ${MAX_RADIOS} radios` }, 409);
  await changed(sub);
  return c.json({ id: created, radios: await radiosOf(sub) }, 201);
});

meRadioRoutes.patch("/:id", async (c) => {
  const sub = c.get("session").user.id;
  const body = z.object({ label: z.string().trim().min(1).max(40).optional(), primary: z.literal(true).optional() }).safeParse(await c.req.json().catch(() => null));
  if (!body.success) return c.json({ error: body.error.issues[0]?.message ?? "bad request" }, 400);
  const id = c.req.param("id");
  const ok = await tx(async (t) => {
    const { rowCount } = await t.query(`SELECT 1 FROM user_radio WHERE id = $1 AND sub = $2`, [id, sub]);
    if (!rowCount) return false;
    if (body.data.label) await t.query(`UPDATE user_radio SET label = $3 WHERE id = $1 AND sub = $2`, [id, sub, body.data.label]);
    if (body.data.primary) {
      await t.query(`UPDATE user_radio SET is_primary = (id = $1) WHERE sub = $2`, [id, sub]);
    }
    return true;
  });
  if (!ok) return c.json({ error: "not found" }, 404);
  await changed(sub);
  return c.json({ radios: await radiosOf(sub) });
});

/** Reorder: the full list of ids in the new order. */
meRadioRoutes.put("/order", async (c) => {
  const sub = c.get("session").user.id;
  const body = z.object({ ids: z.array(z.string()).max(MAX_RADIOS) }).safeParse(await c.req.json().catch(() => null));
  if (!body.success) return c.json({ error: "expected {ids: [...]}" }, 400);
  await q(
    `UPDATE user_radio r SET sort_order = o.pos FROM unnest($2::text[]) WITH ORDINALITY AS o(id, pos) WHERE r.id = o.id AND r.sub = $1`,
    [sub, body.data.ids],
  );
  await changed(sub);
  return c.json({ radios: await radiosOf(sub) });
});

meRadioRoutes.delete("/:id", async (c) => {
  const sub = c.get("session").user.id;
  const gone = await tx(async (t) => {
    const { rows } = await t.query<{ is_primary: boolean }>(`DELETE FROM user_radio WHERE id = $1 AND sub = $2 RETURNING is_primary`, [c.req.param("id"), sub]);
    if (!rows[0]) return false;
    // Keep one primary while any radio is left.
    if (rows[0].is_primary) {
      await t.query(
        `UPDATE user_radio SET is_primary = true WHERE id = (SELECT id FROM user_radio WHERE sub = $1 ORDER BY sort_order, created_at LIMIT 1)`,
        [sub],
      );
    }
    return true;
  });
  if (!gone) return c.json({ error: "not found" }, 404);
  await changed(sub);
  return c.body(null, 204);
});
