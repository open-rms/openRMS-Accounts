import { serve } from "@hono/node-server";
import { createApp } from "./app.js";
import { env } from "./env.js";
import { startDispatcher } from "./events.js";
import { migrate } from "./migrate.js";

await migrate();
startDispatcher();
serve({ fetch: createApp().fetch, port: env.PORT }, (i) => console.log(`openRMS Accounts on http://localhost:${i.port} (issuer ${env.ISSUER})`));
