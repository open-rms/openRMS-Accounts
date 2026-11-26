<script lang="ts">
  // The link in the "your account will be deleted" email: cancels without signing in.
  import { page } from "$app/state";
  import { api } from "#lib/api.ts";
  import { Button } from "#lib/components/ui/button/index.ts";

  const token = page.url.searchParams.get("token") ?? "";
  let done = $state(false), err = $state(""), busy = $state(false);
  async function cancel() {
    busy = true;
    err = "";
    try {
      await api.cancelDeletionByLink(token);
      done = true;
    } catch (x) {
      err = (x as Error).message;
    } finally {
      busy = false;
    }
  }
</script>

<div class="mx-auto max-w-[440px]">
  <h1>Keep your account</h1>
  {#if done}
    <p>Done: your account won't be deleted. <a href="/login">Sign in</a></p>
  {:else if !token}
    <p class="text-destructive">This link is incomplete. Sign in and cancel on your account page instead.</p>
  {:else}
    <p>Your openRMS account is set to be deleted. Cancel that?</p>
    <Button onclick={cancel} disabled={busy}>Keep my account</Button>
    {#if err}<p class="text-destructive">{err}</p>{/if}
  {/if}
</div>
