<script lang="ts">
  import { authClient } from "#lib/auth.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";
  let email = $state(""), sent = $state(false), err = $state(""), busy = $state(false);

  async function submit(e: Event) {
    e.preventDefault();
    busy = true;
    err = "";
    const { error } = await authClient.requestPasswordReset({ email, redirectTo: `${location.origin}/reset-password` });
    busy = false;
    if (error) err = error.message ?? "Request failed";
    else sent = true;
  }
</script>

<div class="mx-auto max-w-[400px]">
  <h1>Reset your password</h1>
  {#if sent}
    <p>If an account uses <b>{email}</b>, we've sent it a link to set a new password.</p>
  {:else}
    <form onsubmit={submit}>
      <Card.Root>
        <Card.Content class="flex flex-col gap-3">
          <div class="grid gap-1.5"><Label for="e">Email</Label><Input id="e" type="email" required autocomplete="email" bind:value={email} /></div>
          {#if err}<p class="text-destructive my-0">{err}</p>{/if}
          <div><Button type="submit" disabled={busy}>Send reset link</Button></div>
        </Card.Content>
      </Card.Root>
    </form>
  {/if}
  <p><a href="/login">Back to sign-in</a></p>
</div>
