<script lang="ts">
  import { goto } from "$app/navigation";
  import { authClient, session } from "#lib/auth.ts";
  import { api } from "#lib/api.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import { Badge } from "#lib/components/ui/badge/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";
  import * as Table from "#lib/components/ui/table/index.ts";
  import SecurityCard from "#lib/SecurityCard.svelte";

  $effect(() => {
    if (!$session.isPending && !$session.data?.user) goto("/login?next=/account");
  });

  type U = { id: string; name: string; email: string; callsign: string; callsignVerified?: boolean | null; callsignVerifiedMethod?: string | null; gridsquare?: string | null };
  let user = $derived($session.data?.user as U | undefined);

  // Profile
  let name = $state(""), grid = $state(""), profileMsg = $state(""), profileErr = $state("");
  let loadedFor = "";
  $effect(() => {
    if (user && loadedFor !== user.id) {
      loadedFor = user.id;
      name = user.name;
      grid = user.gridsquare ?? "";
    }
  });
  async function saveProfile(e: Event) {
    e.preventDefault();
    profileMsg = profileErr = "";
    const { error } = await authClient.updateUser({ name, gridsquare: grid.trim() || null } as never);
    if (error) profileErr = error.message ?? "Save failed";
    else profileMsg = "Saved. Apps see the change on their next token (within 15 minutes).";
  }

  // Password
  let current = $state(""), next = $state(""), pwMsg = $state(""), pwErr = $state("");
  async function changePassword(e: Event) {
    e.preventDefault();
    pwMsg = pwErr = "";
    const { error } = await authClient.changePassword({ currentPassword: current, newPassword: next, revokeOtherSessions: true });
    if (error) pwErr = error.message ?? "Change failed";
    else {
      pwMsg = "Password changed. Other sessions and linked devices are signed out.";
      current = next = "";
      loadSessions();
    }
  }

  // Sessions and connected apps
  type S = { id: string; token: string; userAgent?: string | null; ipAddress?: string | null; createdAt: string | Date; updatedAt: string | Date };
  let sessions = $state<S[]>([]);
  async function loadSessions() {
    const { data } = await authClient.listSessions();
    sessions = (data ?? []) as S[];
  }
  async function revoke(s: S) {
    await authClient.revokeSession({ token: s.token });
    loadSessions();
  }
  type C = { id: string; clientId: string; scopes: string[] | string; createdAt: string };
  let apps = $state<C[]>([]);
  async function loadApps() {
    apps = await api.consents().catch(() => []);
  }
  async function disconnect(c: C) {
    if (!window.confirm(`Disconnect ${c.clientId}? It has to ask again next time.`)) return;
    await api.revokeConsent(c.id);
    loadApps();
  }
  $effect(() => {
    if (user) {
      loadSessions();
      loadApps();
    }
  });
  const fmt = (d: string | Date) => new Date(d).toLocaleString();
</script>

{#if user}
  <h1>Your account</h1>

  <Card.Root class="mb-5">
    <Card.Header><Card.Title><h2 class="m-0">Callsign</h2></Card.Title></Card.Header>
    <Card.Content class="flex flex-wrap items-center gap-3">
      <span class="font-mono text-xl font-bold">{user.callsign}</span>
      {#if user.callsignVerified}<Badge variant="open">verified ({user.callsignVerifiedMethod ?? "moderator"})</Badge>
      {:else}<Badge variant="outline">not yet verified</Badge>{/if}
      <p class="text-muted-foreground m-0 w-full text-sm">
        Your callsign can't be changed here, because apps list things under it. Ask a moderator if it changes. Extra or club
        callsigns go under <a href="/clubs">Clubs</a>.
      </p>
    </Card.Content>
  </Card.Root>

  <Card.Root class="mb-5">
    <Card.Header><Card.Title><h2 class="m-0">Profile</h2></Card.Title></Card.Header>
    <Card.Content>
      <form class="grid max-w-[420px] gap-3" onsubmit={saveProfile}>
        <div class="grid gap-1.5"><Label for="n">Name</Label><Input id="n" required bind:value={name} /></div>
        <div class="grid gap-1.5"><Label for="g">Home grid</Label><Input id="g" placeholder="DN16" bind:value={grid} /></div>
        <div class="grid gap-1.5"><Label>Email</Label><span>{user.email}</span></div>
        {#if profileErr}<p class="text-destructive m-0">{profileErr}</p>{/if}
        {#if profileMsg}<p class="m-0">{profileMsg}</p>{/if}
        <div><Button type="submit">Save</Button></div>
      </form>
    </Card.Content>
  </Card.Root>

  <Card.Root class="mb-5">
    <Card.Header><Card.Title><h2 class="m-0">Password</h2></Card.Title></Card.Header>
    <Card.Content>
      <form class="grid max-w-[420px] gap-3" onsubmit={changePassword}>
        <div class="grid gap-1.5"><Label for="c">Current password</Label><Input id="c" type="password" required autocomplete="current-password" bind:value={current} /></div>
        <div class="grid gap-1.5"><Label for="np">New password (10+ characters)</Label><Input id="np" type="password" minlength={10} required autocomplete="new-password" bind:value={next} /></div>
        {#if pwErr}<p class="text-destructive m-0">{pwErr}</p>{/if}
        {#if pwMsg}<p class="m-0">{pwMsg}</p>{/if}
        <div><Button type="submit">Change password</Button></div>
      </form>
    </Card.Content>
  </Card.Root>

  <SecurityCard />

  <Card.Root class="mb-5">
    <Card.Header>
      <Card.Title><h2 class="m-0">Signed-in browsers</h2></Card.Title>
      <Card.Description>Every openRMS app shares these sessions.</Card.Description>
    </Card.Header>
    <Card.Content>
      <Table.Root>
        <Table.Header><Table.Row><Table.Head>Browser</Table.Head><Table.Head>Last active</Table.Head><Table.Head></Table.Head></Table.Row></Table.Header>
        <Table.Body>
          {#each sessions as s (s.id)}
            <Table.Row>
              <Table.Cell class="max-w-[420px] truncate text-sm">{s.userAgent ?? "unknown"}{s.ipAddress ? ` · ${s.ipAddress}` : ""}</Table.Cell>
              <Table.Cell class="text-sm">{fmt(s.updatedAt)}</Table.Cell>
              <Table.Cell class="text-right">
                {#if s.id === $session.data?.session?.id}<Badge variant="outline">this one</Badge>
                {:else}<Button variant="outline" size="sm" onclick={() => revoke(s)}>Sign out</Button>{/if}
              </Table.Cell>
            </Table.Row>
          {/each}
        </Table.Body>
      </Table.Root>
    </Card.Content>
  </Card.Root>

  <Card.Root class="mb-5">
    <Card.Header>
      <Card.Title><h2 class="m-0">Connected apps</h2></Card.Title>
      <Card.Description>Third-party apps you've allowed to use your account. openRMS's own apps and linked devices aren't listed.</Card.Description>
    </Card.Header>
    <Card.Content>
      {#if apps.length === 0}
        <p class="text-muted-foreground m-0">None.</p>
      {:else}
        <Table.Root>
          <Table.Body>
            {#each apps as c (c.id)}
              <Table.Row>
                <Table.Cell class="font-mono">{c.clientId}</Table.Cell>
                <Table.Cell class="text-sm">{Array.isArray(c.scopes) ? c.scopes.join(" ") : c.scopes}</Table.Cell>
                <Table.Cell class="text-right"><Button variant="outline" size="sm" onclick={() => disconnect(c)}>Disconnect</Button></Table.Cell>
              </Table.Row>
            {/each}
          </Table.Body>
        </Table.Root>
      {/if}
    </Card.Content>
  </Card.Root>
{/if}
