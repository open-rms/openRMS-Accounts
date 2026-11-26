<script lang="ts">
  // Your data (openRMS-Spec/accounts/identity.md §4c): download it, or delete the account after
  // a grace period.
  import { goto } from "$app/navigation";
  import { api } from "#lib/api.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";

  let { callsign }: { callsign: string } = $props();
  let info = $state<{ pending: string | null; graceDays: number; soleOwnerOf: string[]; fresh: boolean; superadmin: boolean } | null>(null);
  let open = $state(false), password = $state(""), confirm = $state(""), err = $state(""), busy = $state(false);
  const load = async () => (info = await api.deletion().catch(() => null));
  $effect(() => {
    load();
  });

  async function remove(e: Event) {
    e.preventDefault();
    err = "";
    busy = true;
    try {
      await api.requestDeletion(password, confirm);
      // Signed out everywhere; the email has the cancel link.
      goto("/login?deleted=1");
    } catch (x) {
      err = (x as Error).message;
    } finally {
      busy = false;
    }
  }
  async function cancel() {
    await api.cancelDeletion();
    await load();
  }
</script>

<Card.Root class="mb-5" id="data">
  <Card.Header>
    <Card.Title><h2 class="m-0">Your data</h2></Card.Title>
    <Card.Description>What openRMS Accounts holds about you. Atlas and Rigs keep their own data; export or delete it there.</Card.Description>
  </Card.Header>
  <Card.Content class="grid gap-5">
    <div><a href="/api/v1/me/account/export" download><Button variant="outline">Download my data (JSON)</Button></a></div>

    {#if info?.pending}
      <div class="border-destructive flex flex-wrap items-center gap-3 rounded border p-3">
        <span>Your account will be deleted on <b>{new Date(info.pending).toLocaleString()}</b>.</span>
        <Button onclick={cancel}>Keep my account</Button>
      </div>
    {:else if info}
      <section class="grid gap-3">
        <h3 class="m-0">Delete my account</h3>
        {#if info.superadmin}
          <p class="m-0 text-sm">A superadmin can't delete their own account. Hand the role to someone else first.</p>
        {:else if info.soleOwnerOf.length}
          <p class="m-0 text-sm">You're the only owner of {info.soleOwnerOf.join(", ")}. Make someone else owner, or delete the club, under <a href="/clubs">Clubs</a> first.</p>
        {:else if !open}
          <p class="text-muted-foreground m-0 text-sm">
            Your account, callsign and everything above go after {info.graceDays} days, and every openRMS service is told to delete what it holds.
            Until then you can change your mind.
          </p>
          <div><Button variant="destructive" onclick={() => (open = true)}>Delete my account…</Button></div>
        {:else if !info.fresh}
          <p class="m-0 text-sm">For your safety, <a href="/login?next=%2Faccount%23data">sign in again</a> first (it's been more than 15 minutes).</p>
        {:else}
          <form class="grid max-w-[420px] gap-3" onsubmit={remove}>
            <div class="grid gap-1.5"><Label for="dp">Password</Label><Input id="dp" type="password" required autocomplete="current-password" bind:value={password} /></div>
            <div class="grid gap-1.5"><Label for="dc">Type <b>{callsign}</b> to confirm</Label><Input id="dc" required autocomplete="off" bind:value={confirm} /></div>
            {#if err}<p class="text-destructive m-0">{err}</p>{/if}
            <div class="flex gap-3">
              <Button type="submit" variant="destructive" disabled={busy || confirm.trim().toUpperCase() !== callsign}>Delete in {info.graceDays} days</Button>
              <Button type="button" variant="outline" onclick={() => (open = false)}>Cancel</Button>
            </div>
          </form>
        {/if}
      </section>
    {/if}
  </Card.Content>
</Card.Root>
