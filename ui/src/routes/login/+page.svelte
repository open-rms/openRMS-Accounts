<script lang="ts">
  import { page } from "$app/state";
  import { authClient } from "#lib/auth.ts";
  import { appName, safeNext } from "#lib/api.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";

  // Two ways here: an app sent the user (?next=<url on a trusted app>), or the OAuth provider did
  // (signed authorization query in the URL; the client plugin resumes it after sign-in).
  const nextRaw = page.url.searchParams.get("next");
  const isOAuth = page.url.searchParams.has("sig");
  let returningTo = $state<string | null>(null);
  $effect(() => {
    if (nextRaw) appName(nextRaw).then((n) => (returningTo = n));
  });
  const carry = page.url.search; // keep next / OAuth query on links to sign-up and reset

  let email = $state(""), password = $state(""), err = $state(""), busy = $state(false);

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    err = "";
    const { data, error } = await authClient.signIn.email({ email, password });
    if (error) {
      busy = false;
      err = error.message ?? "Sign-in failed";
      return;
    }
    // Second factor on: the OAuth query and ?next ride along in the URL to the next step.
    if ((data as { twoFactorRedirect?: boolean } | null)?.twoFactorRedirect) {
      location.href = `/two-factor${carry}`;
      return;
    }
    await finish(data);
  }

  async function finish(data: unknown) {
    const url = (data as { url?: string } | null)?.url;
    if (isOAuth && url) location.href = url;
    else location.href = await safeNext(nextRaw);
  }

  // A passkey is a full sign-in on its own (no password, no second step).
  async function withPasskey() {
    err = "";
    const res = await authClient.signIn.passkey();
    if (res?.error) {
      err = res.error.message ?? "Passkey sign-in failed";
      return;
    }
    await finish(res?.data);
  }
  // Offer saved passkeys in the email field's autofill where the browser supports it.
  $effect(() => {
    if (typeof PublicKeyCredential !== "undefined" && PublicKeyCredential.isConditionalMediationAvailable) {
      PublicKeyCredential.isConditionalMediationAvailable().then((ok) => {
        if (ok) authClient.signIn.passkey({ autoFill: true }).then((res) => { if (res && !res.error && res.data) finish(res.data); }).catch(() => {});
      });
    }
  });
</script>

<div class="mx-auto max-w-[400px]">
  <h1>Sign in</h1>
  {#if returningTo}<p class="text-muted-foreground">to continue to <b>{returningTo}</b></p>{/if}
  <form onsubmit={submit}>
    <Card.Root>
      <Card.Content class="flex flex-col gap-3">
        <div class="grid gap-1.5"><Label for="e">Email</Label><Input id="e" type="email" required autocomplete="username webauthn" bind:value={email} /></div>
        <div class="grid gap-1.5"><Label for="p">Password</Label><Input id="p" type="password" required autocomplete="current-password" bind:value={password} /></div>
        {#if err}<p class="text-destructive my-0">{err}</p>{/if}
        <div class="flex items-center gap-4">
          <Button type="submit" disabled={busy}>Sign in</Button>
          <a class="text-sm" href="/forgot-password">Forgot password?</a>
        </div>
        <div class="border-t pt-3"><Button type="button" variant="outline" onclick={withPasskey}>Sign in with a passkey</Button></div>
      </Card.Content>
    </Card.Root>
  </form>
  <p>No account? <a href="/signup{carry}">Create one</a></p>
</div>
