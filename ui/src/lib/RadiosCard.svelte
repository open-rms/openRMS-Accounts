<script lang="ts">
  // "My radios" (openRMS-Spec/accounts/identity.md §4): picked from the Rigs catalog, keyed by
  // the Hamlib macro, with the user's own label. Rigs and rigctlWeb show your radios first.
  import { api, uiConfig, type Radio } from "#lib/api.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import { Badge } from "#lib/components/ui/badge/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";

  type Hit = { macro: string; hamlib_model: number; mfg: string; name: string; status: string };
  let radios = $state<Radio[]>([]), max = $state(20), err = $state("");
  let catalog = $state<string | null>(null);
  let query = $state(""), hits = $state<Hit[]>([]), picked = $state<Hit | null>(null), label = $state(""), searching = $state(false);

  const load = async () => ({ radios, max } = await api.radios());
  $effect(() => {
    load();
    uiConfig().then((c) => (catalog = c.rigsCatalog ?? null));
  });

  let timer: ReturnType<typeof setTimeout> | undefined;
  function search() {
    clearTimeout(timer);
    picked = null;
    const term = query.trim();
    if (!catalog || term.length < 2) return void (hits = []);
    timer = setTimeout(async () => {
      searching = true;
      try {
        const r = await fetch(`${catalog}?q=${encodeURIComponent(term)}`);
        hits = r.ok ? ((await r.json()) as { rigs: Hit[] }).rigs.slice(0, 12) : [];
      } catch {
        hits = [];
      } finally {
        searching = false;
      }
    }, 250);
  }

  function choose(h: Hit) {
    picked = h;
    label = h.name;
    hits = [];
    query = `${h.mfg} ${h.name}`;
  }

  async function add(e: Event) {
    e.preventDefault();
    if (!picked) return;
    err = "";
    try {
      ({ radios } = await api.addRadio({ model: picked.macro, hamlib_model: picked.hamlib_model, label: label.trim() || picked.name }));
      picked = null;
      query = label = "";
    } catch (x) {
      err = (x as Error).message;
    }
  }
  const act = async (fn: () => Promise<{ radios: Radio[] } | void>) => {
    err = "";
    try {
      const r = await fn();
      if (r) radios = r.radios;
      else await load();
    } catch (x) {
      err = (x as Error).message;
    }
  };
  async function rename(r: Radio) {
    const next = window.prompt("Name for this radio", r.label)?.trim();
    if (next && next !== r.label) await act(() => api.updateRadio(r.id, { label: next }));
  }
</script>

<Card.Root class="mb-5" id="radios">
  <Card.Header>
    <Card.Title><h2 class="m-0">My radios</h2></Card.Title>
    <Card.Description>openRMS Rigs and apps like rigctlWeb show profiles for your radios first.</Card.Description>
  </Card.Header>
  <Card.Content class="grid gap-4">
    {#if radios.length}
      <ul class="m-0 grid list-none gap-2 p-0">
        {#each radios as r (r.id)}
          <li class="flex flex-wrap items-center gap-2 rounded border p-2">
            <span class="font-medium">{r.label}</span>
            <code class="text-muted-foreground text-xs">{r.model}</code>
            {#if r.primary}<Badge variant="open">main radio</Badge>{/if}
            <span class="ml-auto flex gap-2">
              {#if !r.primary}<Button variant="outline" size="sm" onclick={() => act(() => api.updateRadio(r.id, { primary: true }))}>Make main</Button>{/if}
              <Button variant="outline" size="sm" onclick={() => rename(r)}>Rename</Button>
              <Button variant="outline" size="sm" onclick={() => act(() => api.removeRadio(r.id))}>Remove</Button>
            </span>
          </li>
        {/each}
      </ul>
    {:else}
      <p class="text-muted-foreground m-0">No radios yet.</p>
    {/if}

    {#if radios.length < max}
      {#if catalog}
        <form class="grid max-w-[520px] gap-2" onsubmit={add}>
          <Label for="rq">Add a radio</Label>
          <div class="relative">
            <Input id="rq" autocomplete="off" placeholder="Search models, e.g. IC-7300 or FTDX10" bind:value={query} oninput={search} />
            {#if hits.length}
              <ul class="bg-popover absolute z-10 m-0 mt-1 max-h-72 w-full list-none overflow-auto rounded border p-1 shadow" role="listbox">
                {#each hits as h (h.macro)}
                  <li>
                    <button type="button" role="option" aria-selected="false" class="hover:bg-muted w-full rounded px-2 py-1 text-left" onclick={() => choose(h)}>
                      {h.mfg} {h.name} <span class="text-muted-foreground text-xs">{h.status}</span>
                    </button>
                  </li>
                {/each}
              </ul>
            {:else if searching}<p class="text-muted-foreground m-0 text-sm">Searching…</p>{/if}
          </div>
          {#if picked}
            <div class="grid gap-1.5">
              <Label for="rl">Your name for it</Label>
              <Input id="rl" maxlength={40} bind:value={label} />
              <p class="text-muted-foreground m-0 text-xs">Hamlib model {picked.macro}. One model can cover several radios (e.g. FT-991 and FT-991A): name yours.</p>
            </div>
            <div><Button type="submit">Add radio</Button></div>
          {/if}
        </form>
      {:else}
        <p class="text-muted-foreground m-0 text-sm">The radio catalog isn't available right now.</p>
      {/if}
    {/if}
    {#if err}<p class="text-destructive m-0">{err}</p>{/if}
  </Card.Content>
</Card.Root>
