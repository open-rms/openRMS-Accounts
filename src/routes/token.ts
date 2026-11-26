// First-party tokens (spec §3a). A signed-in browser on a trusted origin trades its session
// cookie for a short-lived access token for one service: GET /api/v1/token?aud=<service>.
import { Hono } from "hono";
import { auth } from "../auth.js";
import { buildClaims, FIRST_PARTY_SCOPES } from "../claims.js";
import { env } from "../env.js";

export const tokenRoutes = new Hono();

const TTL_S = 15 * 60;

tokenRoutes.get("/", async (c) => {
  const aud = (c.req.query("aud") ?? "").replace(/\/+$/, "");
  if (!env.firstPartyAudiences.includes(aud)) {
    return c.json({ error: "invalid_target", error_description: `aud must be one of ${env.firstPartyAudiences.join(", ")}` }, 400);
  }
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session) return c.json({ error: "sign in required" }, 401);
  const user = session.user as typeof session.user & { banned?: boolean | null };
  if (user.banned) return c.json({ error: "account banned" }, 403);
  const iat = Math.floor(Date.now() / 1000);
  const exp = iat + TTL_S;
  const claims = await buildClaims({ id: user.id }, FIRST_PARTY_SCOPES, true);
  const { token } = await auth.api.signJWT({
    body: {
      payload: { ...claims, sub: user.id, aud, iss: env.ISSUER, iat, exp, sid: session.session.id, scope: FIRST_PARTY_SCOPES.join(" ") },
    },
  });
  c.header("Cache-Control", "no-store");
  return c.json({ token, token_type: "Bearer", expires_in: TTL_S, expires_at: exp });
});
