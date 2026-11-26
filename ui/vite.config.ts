import { sveltekit } from "@sveltejs/kit/vite";
import tailwindcss from "@tailwindcss/vite";
import adapter from "@sveltejs/adapter-static";
import { defineConfig } from "vite";

// The Accounts pages are a static SPA served by openRMS-Accounts itself (same origin as its API),
// built into ui/build. For UI work, `pnpm dev` here proxies the API to a running Accounts.
const ACCOUNTS = (globalThis as any).process?.env?.ACCOUNTS_URL ?? "http://localhost:8789";

export default defineConfig({
  plugins: [tailwindcss(), sveltekit({ adapter: adapter({ fallback: "index.html" }) })],
  server: { port: 5175, proxy: { "/api": ACCOUNTS, "/.well-known": ACCOUNTS } },
});
