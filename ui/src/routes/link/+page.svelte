<script lang="ts">
  // Device linking (RFC 8628): a device (openRMS-Watch, rigctlWeb, hamstack, ...) shows a code;
  // approving it here gives that device a token for one openRMS service. The device then does the
  // rest with that service itself (Watch picks or creates its watcher with Atlas).
  import { page } from "$app/state";
  import { goto } from "$app/navigation";
  import { session } from "#lib/auth.ts";
  import { api } from "#lib/api.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";

  let userCode = $state(page.url.searchParams.get("user_code") ?? "");
  let err = $state(""), busy = $state(false), result = $state<"approved" | "denied" | null>(null);

  $effect(() => {
    if (!$session.isPending && !$session.data?.user) goto(`/login?next=${encodeURIComponent(page.url.pathname + page.url.search)}`);
  });

  async function decide(decision: "approve" | "deny") {
    err = "";
    busy = true;
    try {
      await api.device(userCode, decision);
      result = decision === "approve" ? "approved" : "denied";
    } catch (x) {
      err = (x as Error).message;
    } finally {
      busy = false;
    }
  }
</script>

<div class="mx-auto max-w-[460px]">
  <h1>Link a device</h1>
  {#if result === "approved"}
    <Card.Root>
      <Card.Content>
        <p class="mt-0"><b>Approved.</b> Go back to your device: it finishes linking within a few seconds.</p>
        <p class="mb-0 text-sm text-muted-foreground">
          An openRMS-Watch receiver then asks which of your watchers it is (or creates one) and gets its own upload key, which you
          can revoke from your Atlas dashboard. Changing your password signs every linked device out.
        </p>
      </Card.Content>
    </Card.Root>
  {:else if result === "denied"}
    <p>Denied. The device won't get access. If you didn't start this, nothing else is needed.</p>
  {:else if $session.data?.user}
    <p class="text-muted-foreground">Enter the code your device shows. Signed in as <span class="font-mono">{$session.data.user.callsign}</span>.</p>
    <Card.Root>
      <Card.Content>
        <form class="grid gap-4" onsubmit={(e) => { e.preventDefault(); decide("approve"); }}>
          <div class="grid gap-1.5">
            <Label for="uc">Code from the device</Label>
            <Input id="uc" class="font-mono text-lg tracking-widest uppercase" bind:value={userCode} required autocomplete="off" />
          </div>
          {#if err}<p class="m-0 text-destructive">{err}</p>{/if}
          <div class="flex gap-3">
            <Button type="submit" disabled={busy || !userCode.trim()}>Approve</Button>
            <Button type="button" variant="outline" disabled={busy || !userCode.trim()} onclick={() => decide("deny")}>Deny</Button>
          </div>
        </form>
      </Card.Content>
    </Card.Root>
    <p class="text-xs text-muted-foreground">Only approve a code you see on your own device. Approving lets that device act for your account.</p>
  {/if}
</div>
