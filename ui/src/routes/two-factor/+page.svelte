<script lang="ts">
  import { page } from "$app/state";
  import { authClient } from "#lib/auth.ts";
  import { safeNext } from "#lib/api.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";

  // Second step of a password sign-in. The URL still carries ?next or the signed OAuth query from
  // /login, so the OAuth client plugin can resume an app's authorization once this succeeds.
  const nextRaw = page.url.searchParams.get("next");
  const isOAuth = page.url.searchParams.has("sig");

  let backup = $state(false), code = $state(""), trust = $state(false), err = $state(""), busy = $state(false);

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    err = "";
    const clean = backup ? code.trim() : code.replace(/\s+/g, "");
    const { data, error } = backup
      ? await authClient.twoFactor.verifyBackupCode({ code: clean, trustDevice: trust })
      : await authClient.twoFactor.verifyTotp({ code: clean, trustDevice: trust });
    if (error) {
      busy = false;
      err = error.message ?? "That code didn't work";
      return;
    }
    const url = (data as { url?: string } | null)?.url;
    if (isOAuth && url) location.href = url;
    else location.href = await safeNext(nextRaw);
  }
</script>

<div class="mx-auto max-w-[400px]">
  <h1>Two-factor sign-in</h1>
  <form onsubmit={submit}>
    <Card.Root>
      <Card.Content class="flex flex-col gap-3">
        {#if backup}
          <div class="grid gap-1.5">
            <Label for="c">Backup code</Label>
            <Input id="c" required autocomplete="off" bind:value={code} />
            <p class="text-muted-foreground m-0 text-sm">Each backup code works once.</p>
          </div>
        {:else}
          <div class="grid gap-1.5">
            <Label for="c">Code from your authenticator app</Label>
            <Input id="c" required inputmode="numeric" autocomplete="one-time-code" pattern="[0-9 ]{'{6,7}'}" maxlength={7} bind:value={code} />
          </div>
        {/if}
        <label class="flex items-center gap-2 text-sm"><input type="checkbox" bind:checked={trust} /> Trust this browser for 30 days</label>
        {#if err}<p class="text-destructive my-0">{err}</p>{/if}
        <div class="flex items-center gap-4">
          <Button type="submit" disabled={busy}>Continue</Button>
          <button type="button" class="text-sm underline" onclick={() => { backup = !backup; code = ""; err = ""; }}>
            {backup ? "Use the authenticator app" : "Use a backup code"}
          </button>
        </div>
      </Card.Content>
    </Card.Root>
  </form>
  <p class="text-muted-foreground text-sm">Lost your authenticator and your backup codes? Ask openRMS staff to reset two-factor sign-in after they confirm who you are.</p>
  <p><a href="/login{page.url.search}">Start again</a></p>
</div>
