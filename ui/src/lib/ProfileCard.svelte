<script lang="ts">
  // Profile fields and who sees each (openRMS-Spec/accounts/identity.md §4a). Name and grid live
  // on the Better Auth user (updateUser); the rest and every visibility go to /api/v1/me/profile.
  import { authClient } from "#lib/auth.ts";
  import { api, type AvatarSource, type Level, type ProfileField, type ProfileLink } from "#lib/api.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";

  let { user }: { user: { id: string; name: string; email: string; callsign: string; gridsquare?: string | null } } = $props();

  let name = $state(""), grid = $state(""), bio = $state(""), city = $state(""), links = $state<ProfileLink[]>([]), hidden = $state(false);
  let vis = $state<Record<ProfileField, Level>>({ name: "members", grid: "private", city: "private", bio: "public", links: "public", avatar: "public" });
  let msg = $state(""), err = $state(""), busy = $state(false), loadedFor = "";
  let avatarSource = $state<AvatarSource>("none"), avatarUrl = $state(""), avatarPreview = $state<string | null>(null);

  $effect(() => {
    if (user && loadedFor !== user.id) {
      loadedFor = user.id;
      name = user.name;
      grid = user.gridsquare ?? "";
      api.myProfile().then((p) => {
        bio = p.bio ?? "";
        city = p.city ?? "";
        links = p.links;
        vis = p.visibility;
        hidden = p.hidden;
        avatarSource = p.avatarSource;
        avatarUrl = p.avatarUrl ?? "";
        avatarPreview = p.avatarPreview ?? null;
      });
    }
  });

  const LEVELS: { value: Level; label: string }[] = [
    { value: "public", label: "Everyone" },
    { value: "members", label: "Signed-in openRMS users" },
    { value: "private", label: "Only me" },
  ];

  async function save(e: Event) {
    e.preventDefault();
    msg = err = "";
    busy = true;
    try {
      const { error } = await authClient.updateUser({ name, gridsquare: grid.trim() || null } as never);
      if (error) throw new Error(error.message ?? "Save failed");
      await api.saveProfile({
        bio, city, links: links.filter((l) => l.url.trim()), visibility: vis, hidden,
        avatar: { source: avatarSource, url: avatarSource === "url" ? avatarUrl.trim() : null },
      });
      avatarPreview = (await api.myProfile()).avatarPreview ?? null;
      msg = "Saved. Apps see the change on their next token (within 15 minutes).";
    } catch (x) {
      err = (x as Error).message;
    } finally {
      busy = false;
    }
  }
</script>

{#snippet who(field: ProfileField, id: string)}
  <select id={id} aria-label="Who can see this" class="border-input bg-background h-8 rounded-md border px-1 text-sm" bind:value={vis[field]}>
    {#each LEVELS as l (l.value)}<option value={l.value}>{l.label}</option>{/each}
  </select>
{/snippet}

<Card.Root class="mb-5">
  <Card.Header>
    <Card.Title><h2 class="m-0">Profile</h2></Card.Title>
    <Card.Description>
      Your callsign is always public. Choose who sees everything else on your
      <a href="/u/{user.callsign}">public profile</a> and in apps from other developers.
    </Card.Description>
  </Card.Header>
  <Card.Content>
    <form class="grid max-w-[560px] gap-4" onsubmit={save}>
      <fieldset class="grid gap-2">
        <div class="flex items-center justify-between gap-3"><legend class="text-sm font-medium">Picture</legend>{@render who("avatar", "va")}</div>
        <div class="flex items-start gap-4">
          {#if avatarPreview && avatarSource !== "none"}
            <img src={avatarPreview} alt="" width="64" height="64" class="rounded-full border" />
          {:else}
            <div class="bg-muted flex h-16 w-16 items-center justify-center rounded-full border font-mono text-xs" aria-hidden="true">{user.callsign}</div>
          {/if}
          <div class="grid flex-1 gap-1.5 text-sm">
            <label class="flex items-center gap-2"><input type="radio" value="none" bind:group={avatarSource} /> None (shows your callsign)</label>
            <label class="flex items-start gap-2"><input type="radio" class="mt-1" value="gravatar" bind:group={avatarSource} />
              <span>Gravatar for my email address <span class="text-muted-foreground">(openRMS fetches it for viewers, so Gravatar never sees them, but anyone can check whether a given email has a Gravatar picture)</span></span></label>
            <label class="flex items-center gap-2"><input type="radio" value="url" bind:group={avatarSource} /> A picture on the web</label>
            {#if avatarSource === "url"}
              <Input type="url" placeholder="https://… (PNG, JPEG, WebP or GIF, up to 2 MB)" pattern="https://.*" bind:value={avatarUrl} />
            {/if}
          </div>
        </div>
      </fieldset>
      <div class="grid gap-1.5">
        <div class="flex items-center justify-between gap-3"><Label for="n">Name</Label>{@render who("name", "vn")}</div>
        <Input id="n" required bind:value={name} />
      </div>
      <div class="grid gap-1.5">
        <div class="flex items-center justify-between gap-3"><Label for="g">Home grid</Label>{@render who("grid", "vg")}</div>
        <Input id="g" placeholder="DN16" bind:value={grid} />
        {#if vis.grid === "public"}<p class="text-muted-foreground m-0 text-sm">Everyone sees 4 characters (e.g. {grid.slice(0, 4) || "DN16"}); signed-in users see all of it.</p>{/if}
      </div>
      <div class="grid gap-1.5">
        <div class="flex items-center justify-between gap-3"><Label for="ct">City or area</Label>{@render who("city", "vc")}</div>
        <Input id="ct" maxlength={64} placeholder="Moscow, Idaho" bind:value={city} />
      </div>
      <div class="grid gap-1.5">
        <div class="flex items-center justify-between gap-3"><Label for="bio">About you</Label>{@render who("bio", "vb")}</div>
        <textarea id="bio" maxlength={280} rows={3} class="border-input bg-background rounded-md border p-2 text-sm" bind:value={bio}></textarea>
        <p class="text-muted-foreground m-0 text-right text-xs">{bio.length}/280</p>
      </div>
      <div class="grid gap-1.5">
        <div class="flex items-center justify-between gap-3"><Label>Links</Label>{@render who("links", "vl")}</div>
        {#each links as l, i (i)}
          <div class="flex gap-2">
            <select aria-label="Link type" class="border-input bg-background h-9 rounded-md border px-1 text-sm" bind:value={l.kind}>
              <option value="qrz">QRZ</option><option value="website">Website</option><option value="other">Other</option>
            </select>
            <Input type="url" placeholder="https://" pattern="https://.*" bind:value={l.url} />
            <Button type="button" variant="outline" size="sm" onclick={() => (links = links.filter((_, j) => j !== i))}>Remove</Button>
          </div>
        {/each}
        {#if links.length < 5}
          <div><Button type="button" variant="outline" size="sm" onclick={() => (links = [...links, { kind: links.length ? "website" : "qrz", url: "" }])}>Add a link</Button></div>
        {/if}
      </div>
      <div class="grid gap-1.5"><Label>Email</Label><span>{user.email} <span class="text-muted-foreground text-sm">(never shown on your profile)</span></span></div>
      <label class="flex items-center gap-2"><input type="checkbox" bind:checked={hidden} /> Hide my public profile page</label>
      {#if err}<p class="text-destructive m-0">{err}</p>{/if}
      {#if msg}<p class="m-0">{msg}</p>{/if}
      <div class="flex gap-3"><Button type="submit" disabled={busy}>Save</Button><a class="self-center text-sm" href="/u/{user.callsign}">View your profile</a></div>
    </form>
  </Card.Content>
</Card.Root>
