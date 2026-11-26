import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { env } from "./env.js";
import { startDispatcher } from "./events.js";
import { startKeyReminders } from "./keys.js";
import { migrate } from "./migrate.js";

await migrate();
startDispatcher();
startKeyReminders();
serve({ fetch: createApp().fetch, port: env.PORT, hostname: env.HOST }, (i) =>
  console.log(`openRMS Accounts listening on ${i.address}:${i.port} (issuer ${env.ISSUER})`),
);
