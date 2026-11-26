<script lang="ts">
  // OAuth consent for third-party apps (openRMS's own apps skip it). The provider sends the user
  // here with a signed query; accepting returns them to the app with an authorization code.
  import { page } from "$app/state";
  import { authClient } from "#lib/auth.ts";
  import { api } from "#lib/api.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";

  const clientId = page.url.searchParams.get("client_id") ?? "";
  const scopes = (page.url.searchParams.get("scope") ?? "").split(" ").filter(Boolean);
  const SCOPE_TEXT: Record<string, string> = {
    openid: "Know which openRMS account you are",
    profile: "Your name and home grid",
    email: "Your email address",
    callsign: "Your callsign and whether it's verified",
    clubs: "The clubs and extra callsigns you belong to",
    offline_access: "Stay connected when you're not using it (until you disconnect it here)",
  };
  let client = $state<{ client_name?: string; client_uri?: string } | null>(null);
  let err = $state(""), busy = $state(false);
  $effect(() => {
    if (clientId) api.publicClient(clientId).then((c) => (client = c)).catch(() => (client = { client_name: clientId }));
  });

  async function answer(accept: boolean) {
    busy = true;
    err = "";
    const { data, error } = await authClient.$fetch<{ url?: string; redirect_uri?: string }>("/oauth2/consent", { method: "POST", body: { accept } });
    busy = false;
    if (error) return void (err = error.message ?? "Request failed");
    const url = data?.url ?? data?.redirect_uri;
    if (url) location.href = url;
  }
</script>

<div class="mx-auto max-w-[480px]">
  <h1>Allow access?</h1>
  <Card.Root>
    <Card.Content class="flex flex-col gap-3">
      <p class="m-0"><b>{client?.client_name ?? clientId}</b> wants to use your openRMS account.</p>
      {#if client?.client_uri}<p class="text-muted-foreground m-0 text-sm">{client.client_uri}</p>{/if}
      <ul class="m-0">
        {#each scopes as s}<li>{SCOPE_TEXT[s] ?? s}</li>{/each}
      </ul>
      {#if err}<p class="text-destructive m-0">{err}</p>{/if}
      <div class="flex gap-3">
        <Button disabled={busy} onclick={() => answer(true)}>Allow</Button>
        <Button variant="outline" disabled={busy} onclick={() => answer(false)}>Deny</Button>
      </div>
      <p class="text-muted-foreground m-0 text-xs">You can disconnect it later under Account, Connected apps.</p>
    </Card.Content>
  </Card.Root>
</div>
