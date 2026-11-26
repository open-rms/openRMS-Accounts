<script lang="ts">
  import { page } from "$app/state";
  import { authClient } from "#lib/auth.ts";
  import { appName, safeNext } from "#lib/api.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";

  const nextRaw = page.url.searchParams.get("next");
  const isOAuth = page.url.searchParams.has("sig");
  let returningTo = $state<string | null>(null);
  $effect(() => {
    if (nextRaw) appName(nextRaw).then((n) => (returningTo = n));
  });
  const carry = page.url.search;

  let name = $state(""), email = $state(""), password = $state(""), callsign = $state(""), gridsquare = $state("");
  let err = $state(""), busy = $state(false);
  const CALL = /^[A-Z0-9]{1,3}[0-9][A-Z0-9]{0,3}[A-Z]$/;
  let callOk = $derived(CALL.test(callsign.trim().toUpperCase()));

  async function submit(e: Event) {
    e.preventDefault();
    err = "";
    busy = true;
    const { data, error } = await authClient.signUp.email({
      name, email, password,
      callsign: callsign.trim().toUpperCase(),
      ...(gridsquare.trim() ? { gridsquare: gridsquare.trim() } : {}),
    });
    if (error) {
      busy = false;
      err = error.message ?? "Sign-up failed";
      return;
    }
    const url = (data as { url?: string } | null)?.url;
    if (isOAuth && url) location.href = url;
    else location.href = await safeNext(nextRaw);
  }
</script>

<div class="mx-auto max-w-[440px]">
  <h1>Create an openRMS account</h1>
  <p class="text-muted-foreground">
    One account, with your callsign, for every openRMS app{#if returningTo}, starting with <b>{returningTo}</b>{/if}.
  </p>
  <form onsubmit={submit}>
    <Card.Root>
      <Card.Content class="flex flex-col gap-3">
        <div class="grid gap-1.5">
          <Label for="cs">Callsign</Label>
          <Input id="cs" class="font-mono uppercase" required autocomplete="off" placeholder="W1AW" bind:value={callsign} />
          {#if callsign && !callOk}<div class="text-destructive text-sm">Your bare callsign, without SSID or /P.</div>{/if}
        </div>
        <div class="grid gap-1.5"><Label for="n">Name</Label><Input id="n" required autocomplete="name" bind:value={name} /></div>
        <div class="grid gap-1.5"><Label for="e">Email</Label><Input id="e" type="email" required autocomplete="email" bind:value={email} /></div>
        <div class="grid gap-1.5"><Label for="p">Password (10+ characters)</Label><Input id="p" type="password" minlength={10} required autocomplete="new-password" bind:value={password} /></div>
        <div class="grid gap-1.5"><Label for="g">Home grid (optional)</Label><Input id="g" placeholder="DN16" bind:value={gridsquare} /></div>
        {#if err}<p class="text-destructive my-0">{err}</p>{/if}
        <div><Button type="submit" disabled={busy || !callOk}>Create account</Button></div>
        <p class="text-muted-foreground my-0 text-sm">
          New accounts start with an <b>unverified</b> callsign. Apps show it as unverified until a moderator (or, later, a LoTW
          certificate or on-air check) confirms the callsign is yours.
        </p>
      </Card.Content>
    </Card.Root>
  </form>
  <p>Already have an account? <a href="/login{carry}">Sign in</a></p>
</div>
