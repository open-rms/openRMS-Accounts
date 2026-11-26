// Session middleware for routes used by signed-in browsers (cookie) or apps (bearer session).
import { createMiddleware } from "hono/factory";
import { auth, type Session } from "../auth.js";

export type SessionVars = { Variables: { session: Session } };

export const requireSession = createMiddleware<SessionVars>(async (c, next) => {
  const session = await auth.api.getSession({ headers: c.req.raw.headers });
  if (!session) return c.json({ error: "sign in required" }, 401);
  c.set("session", session);
  await next();
});
