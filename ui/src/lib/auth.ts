import { createAuthClient } from "better-auth/svelte";
import { inferAdditionalFields } from "better-auth/client/plugins";
import { oauthProviderClient } from "@better-auth/oauth-provider/client";

// Same origin as the Accounts API. oauthProviderClient carries an in-progress OAuth authorization
// (the signed query on /login and /consent) through sign-in so the provider can resume it.
export const authClient = createAuthClient({
  basePath: "/api/auth",
  plugins: [
    inferAdditionalFields({
      user: {
        callsign: { type: "string", required: true },
        callsignVerified: { type: "boolean", required: false, input: false },
        callsignVerifiedMethod: { type: "string", required: false, input: false },
        gridsquare: { type: "string", required: false },
      },
    }),
    oauthProviderClient(),
  ],
});

export const session = authClient.useSession();
