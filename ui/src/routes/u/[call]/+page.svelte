<script lang="ts">
  // Public profile (spec §6a): what the server lets this viewer see, nothing more. The owner can
  // preview how strangers and signed-in users see it.
  import { page } from "$app/state";
  import { api, type PublicProfile } from "#lib/api.ts";
  import { Badge } from "#lib/components/ui/badge/index.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";

  let p = $state<PublicProfile | null>(null), missing = $state(false), as = $state<"public" | "members" | undefined>(undefined);
  let isOwner = $state(false);
  $effect(() => {
    const call = page.params.call ?? "";
    missing = false;
    api.profile(call, as)
      .then((r) => {
        p = r;
        if (r.self) isOwner = true;
      })
      .catch(() => {
        p = null;
        missing = true;
      });
  });
  const LINK: Record<string, string> = { qrz: "QRZ", website: "Website", other: "Link" };
  const host = (u: string) => {
    try {
      return new URL(u).host;
    } catch {
      return u;
    }
  };
</script>

<svelte:head><title>{p ? `${p.callsign} · openRMS` : "Profile · openRMS"}</title></svelte:head>

<div class="mx-auto max-w-[560px]">
  {#if missing}
    <h1>No such profile</h1>
    <p class="text-muted-foreground">There's no public openRMS profile for {page.params.call?.toUpperCase()}.</p>
  {:else if p}
    {#if isOwner}
      <div class="text-muted-foreground mb-4 flex flex-wrap items-center gap-2 text-sm">
        Viewing as:
        <Button size="sm" variant={as === undefined ? "default" : "outline"} onclick={() => (as = undefined)}>You</Button>
        <Button size="sm" variant={as === "members" ? "default" : "outline"} onclick={() => (as = "members")}>Signed-in users</Button>
        <Button size="sm" variant={as === "public" ? "default" : "outline"} onclick={() => (as = "public")}>Everyone</Button>
        <a class="ml-auto" href="/account">Edit profile</a>
      </div>
      {#if p.hidden}<p class="border-destructive mb-4 rounded border p-3 text-sm">Your profile is hidden: only you can see this page.</p>{/if}
    {/if}
    <Card.Root>
      <Card.Content class="grid gap-3">
        <div class="flex flex-wrap items-center gap-3">
          <h1 class="m-0 font-mono">{p.callsign}</h1>
          {#if p.callsign_verified}<Badge variant="open">verified callsign</Badge>{/if}
        </div>
        {#if p.name}<p class="m-0 text-lg">{p.name}</p>{/if}
        {#if p.city || p.grid}
          <p class="text-muted-foreground m-0">{[p.city, p.grid].filter(Boolean).join(" · ")}</p>
        {/if}
        {#if p.bio}<p class="m-0 whitespace-pre-line">{p.bio}</p>{/if}
        {#if p.links?.length}
          <ul class="m-0 flex list-none flex-wrap gap-3 p-0">
            {#each p.links as l (l.url)}
              <li><a href={l.url} rel="nofollow noopener noreferrer ugc" target="_blank">{LINK[l.kind] ?? "Link"}: {host(l.url)}</a></li>
            {/each}
          </ul>
        {/if}
        {#if !p.name && !p.bio && !p.city && !p.grid && !p.links?.length}
          <p class="text-muted-foreground m-0 text-sm">{p.callsign} hasn't shared anything else{as === "public" || !isOwner ? " publicly" : ""}.</p>
        {/if}
      </Card.Content>
    </Card.Root>
  {/if}
</div>
