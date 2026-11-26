import { Hono } from "hono";
import { cors } from "hono/cors";
import { logger } from "hono/logger";
import { createMiddleware } from "hono/factory";
import { serveStatic } from "@hono/node-server/serve-static";
import { existsSync, readFileSync, statSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { oauthProviderAuthServerMetadata, oauthProviderOpenIdConfigMetadata } from "@better-auth/oauth-provider";
import { auth } from "./auth.js";
import { env } from "./env.js";
import { adminRoutes } from "./routes/admin.js";
import { keyRoutes, meKeyRoutes, userKeyRoutes } from "./routes/keys.js";
import { meRoutes } from "./routes/me.js";
import { serviceRoutes } from "./routes/service.js";
import { tokenRoutes } from "./routes/token.js";

const UI_DIR = fileURLToPath(new URL("../ui/build", import.meta.url)).replace(/\/$/, "");

export function createApp() {
  const app = new Hono();
  if (process.env.NODE_ENV !== "test") app.use("*", logger());

  // Cookie routes: first-party origins only.
  const firstParty = cors({
    origin: env.trustedOrigins,
    credentials: true,
    allowHeaders: ["Content-Type", "Authorization"],
    allowMethods: ["GET", "POST", "PUT", "DELETE", "OPTIONS"],
  });
  app.use("/api/auth/*", firstParty);
  app.use("/api/v1/me/*", firstParty);
  app.use("/api/v1/me", firstParty);
  app.use("/api/v1/token", firstParty);
  app.use("/api/v1/admin/*", firstParty);
  // CSRF: Better Auth checks Origin on /api/auth/*, but not on our own cookie routes. With a
  // cookie shared across *.openrms.dev, refuse state changes from any other origin. Requests
  // without a cookie (bearer-authenticated apps) carry no ambient credentials and pass.
  const selfOrigin = new URL(env.ISSUER).origin; // the account pages are served from here
  const csrf = createMiddleware(async (c, next) => {
    if (!["GET", "HEAD", "OPTIONS"].includes(c.req.method) && c.req.header("cookie")) {
      const origin = c.req.header("origin");
      if (!origin || !(origin === selfOrigin || env.trustedOrigins.includes(origin))) return c.json({ error: "cross-origin request refused" }, 403);
    }
    await next();
  });
  app.use("/api/v1/me/*", csrf);
  app.use("/api/v1/me", csrf);
  app.use("/api/v1/admin/*", csrf);

  // Discovery and keys are public.
  app.use("/.well-known/*", cors({ origin: "*" }));

  app.on(["GET", "POST"], "/api/auth/*", (c) => auth.handler(c.req.raw));

  // The issuer is the bare origin, so discovery must answer at the root (RFC 8414, OIDC Discovery).
  const oidcConfig = oauthProviderOpenIdConfigMetadata(auth);
  const asConfig = oauthProviderAuthServerMetadata(auth);
  app.get("/.well-known/openid-configuration", (c) => oidcConfig(c.req.raw));
  app.get("/.well-known/oauth-authorization-server", (c) => asConfig(c.req.raw));

  app.route("/api/v1/token", tokenRoutes);
  app.route("/api/v1/me/keys", meKeyRoutes);
  app.route("/api/v1/me", meRoutes);
  app.route("/api/v1/keys", keyRoutes);
  app.route("/api/v1", userKeyRoutes);
  app.route("/api/v1/admin", adminRoutes);
  app.route("/api/v1", serviceRoutes);

  app.get("/api/v1/ui/config", (c) => c.json({ issuer: env.ISSUER, apps: env.apps }));
  app.get("/healthz", (c) => c.json({ ok: true }));
  app.get("/api/v1", (c) => c.json({
    name: "openRMS Accounts",
    issuer: env.ISSUER,
    discovery: `${env.ISSUER}/.well-known/openid-configuration`,
    authReference: "/api/auth/reference",
    spec: "openRMS-Spec/accounts/identity.md",
  }));

  // The account pages (ui/, a static SPA): sign-in, sign-up, /link, /consent, /account, /clubs.
  if (existsSync(UI_DIR)) {
    app.use("/*", serveStatic({ root: UI_DIR }));
    // Re-read when the UI is rebuilt (asset names change on every build).
    let index = { mtime: 0, html: "" };
    const indexHtml = () => {
      const file = `${UI_DIR}/index.html`;
      const mtime = statSync(file).mtimeMs;
      if (mtime !== index.mtime) index = { mtime, html: readFileSync(file, "utf8") };
      return index.html;
    };
    app.get("*", (c) => (c.req.path.startsWith("/api/") ? c.notFound() : c.html(indexHtml())));
  } else {
    app.get("/", (c) => c.text("openRMS Accounts. Build the pages with: cd ui && pnpm build"));
  }
  return app;
}
