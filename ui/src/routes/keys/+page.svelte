<script lang="ts">
  // API keys (openRMS-Spec/accounts/identity.md §5): one key per machine, for one service.
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { session } from "#lib/auth.ts";
  import { api, type ApiKey, type KeyService } from "#lib/api.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import { Badge } from "#lib/components/ui/badge/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";
  import * as Table from "#lib/components/ui/table/index.ts";

  $effect(() => {
    if (!$session.isPending && !$session.data?.user) goto(`/login?next=${encodeURIComponent(page.url.pathname + page.url.search)}`);
  });

  let keys = $state<ApiKey[]>([]), services = $state<KeyService[]>([]), canCreate = $state(true), loaded = $state(false);
  let afterReset = $state(page.url.searchParams.get("after") === "reset");
  async function load() {
    const r = await api.keys();
    keys = r.keys;
    services = r.services;
    canCreate = r.canCreate;
    loaded = true;
    if (!aud && services[0]) aud = services[0].aud;
  }
  $effect(() => {
    if ($session.data?.user) load();
  });

  const serviceName = (a: string) => services.find((s) => s.aud === a)?.name ?? a;
  const live = $derived(keys.filter((k) => !k.revoked_at && new Date(k.expires_at) > new Date()));
  const past = $derived(keys.filter((k) => !live.includes(k)));
  const byJti = $derived(new Map(keys.map((k) => [k.jti, k])));

  // ---- create
  let aud = $state(""), picked = $state<string[]>([]), name = $state(""), days = $state(90), err = $state(""), busy = $state(false);
  let created = $state<(ApiKey & { key: string }) | null>(null), copied = $state(false);
  const svc = $derived(services.find((s) => s.aud === aud));
  $effect(() => {
    void aud;
    picked = [];
  });
  async function create(e: Event) {
    e.preventDefault();
    err = "";
    busy = true;
    try {
      created = await api.createKey({ aud, scopes: picked, name, days });
      copied = false;
      name = "";
      picked = [];
      await load();
    } catch (x) {
      err = (x as Error).message;
    } finally {
      busy = false;
    }
  }
  const curl = (k: ApiKey & { key: string }) => `curl -H "Authorization: Bearer ${k.key}" ${k.aud}/api/v1/...`;

  // ---- revoke
  async function revoke(k: ApiKey) {
    if (!window.confirm(`Revoke "${k.name}"? Whatever uses it stops working within minutes.`)) return;
    await api.revokeKey(k.jti);
    await load();
  }
  let allMsg = $state("");
  async function revokeAll() {
    if (!window.confirm(`Revoke all ${live.length} API keys? Gateways, watchers and scripts using them stop working.`)) return;
    const { revoked } = await api.revokeAllKeys();
    allMsg = `${revoked} key${revoked === 1 ? "" : "s"} revoked.`;
    afterReset = false;
    await load();
  }

  const date = (d: string | null) => (d ? new Date(d).toLocaleDateString() : "never");
  const soon = (d: string) => new Date(d).getTime() - Date.now() < 14 * 86400_000;
  const reasons: Record<string, string> = { revoked: "revoked", "revoke-all": "revoked (all)", renewed: "replaced", banned: "account banned", deleted: "account deleted" };
</script>

{#if $session.data?.user}
  <h1>API keys</h1>
  <p class="text-muted-foreground">
    A key lets a machine (a gateway, a watcher, a script) act for you at one openRMS service, with only the permissions you tick.
    Keys never allow staff actions.
  </p>

  {#if afterReset && live.length}
    <div class="border-destructive mb-5 flex flex-wrap items-center gap-3 rounded border p-3">
      <span>Your password was reset. Your {live.length} API key{live.length === 1 ? "" : "s"} still work. Revoke all of them?</span>
      <Button variant="destructive" size="sm" onclick={revokeAll}>Revoke all API keys</Button>
      <Button variant="outline" size="sm" onclick={() => (afterReset = false)}>Keep them</Button>
    </div>
  {/if}

  {#if created}
    <Card.Root class="border-primary mb-5">
      <Card.Header><Card.Title><h2 class="m-0">Your new key: copy it now</h2></Card.Title>
        <Card.Description>You won't see it again. If you lose it, revoke it and make another.</Card.Description></Card.Header>
      <Card.Content class="grid gap-3">
        <code class="bg-muted block rounded p-3 text-xs break-all" data-testid="new-key">{created.key}</code>
        <div class="flex flex-wrap gap-3">
          <Button onclick={() => navigator.clipboard.writeText(created!.key).then(() => (copied = true))}>{copied ? "Copied" : "Copy"}</Button>
          <Button variant="outline" onclick={() => (created = null)}>Done</Button>
        </div>
        <p class="text-muted-foreground m-0 text-sm">Use it as a bearer token, for example:</p>
        <code class="bg-muted block rounded p-3 text-xs break-all">{curl(created)}</code>
      </Card.Content>
    </Card.Root>
  {/if}

  <Card.Root class="mb-5">
    <Card.Header><Card.Title><h2 class="m-0">Make a key</h2></Card.Title></Card.Header>
    <Card.Content>
      {#if !canCreate}
        <p class="m-0">For your safety, making a key needs a recent sign-in. <a href="/login?next=%2Fkeys">Sign in again</a> to continue.</p>
      {:else if loaded && !services.length}
        <p class="m-0">No services offer API keys yet.</p>
      {:else}
        <form class="grid max-w-[520px] gap-4" onsubmit={create}>
          <div class="grid gap-1.5">
            <Label for="svc">Service</Label>
            <select id="svc" class="border-input bg-background h-9 rounded-md border px-2" bind:value={aud}>
              {#each services as s (s.aud)}<option value={s.aud}>{s.name} ({s.aud})</option>{/each}
            </select>
          </div>
          {#if svc}
            <fieldset class="grid gap-2">
              <legend class="mb-1 text-sm font-medium">Permissions</legend>
              {#each svc.scopes as s (s.scope)}
                <label class="flex items-start gap-2">
                  <input type="checkbox" class="mt-1" value={s.scope} bind:group={picked} />
                  <span><code>{s.scope}</code> <span class="text-muted-foreground text-sm">{s.description}</span></span>
                </label>
              {/each}
            </fieldset>
          {/if}
          <div class="grid gap-1.5"><Label for="kn">Name</Label><Input id="kn" required maxlength={80} placeholder="e.g. W1AW gateway heartbeat" bind:value={name} /></div>
          <div class="grid gap-1.5">
            <Label for="kd">Expires after</Label>
            <select id="kd" class="border-input bg-background h-9 rounded-md border px-2" bind:value={days}>
              <option value={30}>30 days</option><option value={90}>90 days</option><option value={180}>180 days</option><option value={365}>1 year</option>
            </select>
            <p class="text-muted-foreground m-0 text-sm">We email you 14 and 3 days before it expires.</p>
          </div>
          {#if err}<p class="text-destructive m-0">{err}</p>{/if}
          <div><Button type="submit" disabled={busy || !picked.length}>Make key</Button></div>
        </form>
      {/if}
    </Card.Content>
  </Card.Root>

  <Card.Root class="mb-5">
    <Card.Header>
      <Card.Title><h2 class="m-0">Your keys</h2></Card.Title>
      {#if live.length}<Card.Action><Button variant="destructive" size="sm" onclick={revokeAll}>Revoke all</Button></Card.Action>{/if}
    </Card.Header>
    <Card.Content>
      {#if allMsg}<p class="mt-0">{allMsg}</p>{/if}
      {#if !live.length}
        <p class="text-muted-foreground m-0">No active keys.</p>
      {:else}
        <Table.Root>
          <Table.Header><Table.Row><Table.Head>Name</Table.Head><Table.Head>Service and permissions</Table.Head><Table.Head>Last used</Table.Head><Table.Head>Expires</Table.Head><Table.Head></Table.Head></Table.Row></Table.Header>
          <Table.Body>
            {#each live as k (k.jti)}
              <Table.Row>
                <Table.Cell>
                  {k.name}
                  {#if k.renewable}<Badge variant="outline">renews itself</Badge>{/if}
                  {#if k.replaces}<div class="text-muted-foreground text-xs">replaced “{byJti.get(k.replaces)?.name ?? "an earlier key"}” on {date(k.created_at)}</div>{/if}
                </Table.Cell>
                <Table.Cell class="text-sm">{serviceName(k.aud)}: {k.scopes.join(", ")}</Table.Cell>
                <Table.Cell class="text-sm">{date(k.last_used_at)}</Table.Cell>
                <Table.Cell class="text-sm {soon(k.expires_at) && !k.renewable ? 'text-destructive' : ''}">{date(k.expires_at)}</Table.Cell>
                <Table.Cell class="text-right"><Button variant="outline" size="sm" onclick={() => revoke(k)}>Revoke</Button></Table.Cell>
              </Table.Row>
            {/each}
          </Table.Body>
        </Table.Root>
      {/if}
      {#if past.length}
        <details class="mt-4">
          <summary class="text-muted-foreground cursor-pointer text-sm">Revoked and expired (last 30 days)</summary>
          <Table.Root>
            <Table.Body>
              {#each past as k (k.jti)}
                <Table.Row>
                  <Table.Cell>{k.name}</Table.Cell>
                  <Table.Cell class="text-sm">{serviceName(k.aud)}</Table.Cell>
                  <Table.Cell class="text-sm">
                    {#if k.revoked_at}{reasons[k.revoke_reason ?? "revoked"] ?? k.revoke_reason} {date(k.revoked_at)}{:else}expired {date(k.expires_at)}{/if}
                    {#if k.replaced_by}<span class="text-muted-foreground"> → {byJti.get(k.replaced_by)?.name ?? "a newer key"}</span>{/if}
                  </Table.Cell>
                </Table.Row>
              {/each}
            </Table.Body>
          </Table.Root>
        </details>
      {/if}
    </Card.Content>
  </Card.Root>
{/if}
