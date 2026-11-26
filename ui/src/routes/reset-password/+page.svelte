<script lang="ts">
  import { page } from "$app/state";
  import { authClient } from "#lib/auth.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";
  const token = page.url.searchParams.get("token") ?? "";
  const linkError = page.url.searchParams.get("error");
  let password = $state(""), done = $state(false), err = $state(""), busy = $state(false);

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    err = "";
    const { error } = await authClient.resetPassword({ newPassword: password, token });
    busy = false;
    if (error) err = error.message ?? "Reset failed";
    else done = true;
  }
</script>

<div class="mx-auto max-w-[400px]">
  <h1>Choose a new password</h1>
  {#if done}
    <p>Password changed. You've been signed out everywhere, including linked devices; sign in again.</p>
    <p><a href="/login">Sign in</a></p>
  {:else if linkError || !token}
    <p class="text-destructive">This reset link is invalid or has expired.</p>
    <p><a href="/forgot-password">Request a new one</a></p>
  {:else}
    <form onsubmit={submit}>
      <Card.Root>
        <Card.Content class="flex flex-col gap-3">
          <div class="grid gap-1.5"><Label for="p">New password (10+ characters)</Label><Input id="p" type="password" minlength={10} required autocomplete="new-password" bind:value={password} /></div>
          {#if err}<p class="text-destructive my-0">{err}</p>{/if}
          <div><Button type="submit" disabled={busy}>Set password</Button></div>
        </Card.Content>
      </Card.Root>
    </form>
  {/if}
</div>
