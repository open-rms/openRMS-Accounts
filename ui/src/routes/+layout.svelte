<script lang="ts">
  import "../app.css";
  import { goto } from "$app/navigation";
  import { page } from "$app/state";
  import { authClient, session } from "#lib/auth.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  let { children } = $props();

  async function signOut() {
    await authClient.signOut();
    goto("/login");
  }
  const nav = [
    { href: "/account", label: "Account" },
    { href: "/clubs", label: "Clubs" },
  ];
</script>

<header class="bg-card mb-5 border-b">
  <div class="mx-auto flex min-h-14 max-w-[900px] flex-wrap items-center gap-6 px-4">
    <a class="text-foreground flex items-center gap-2 text-[1.05rem] no-underline" href="/account">
      <img src="/favicon.svg" alt="" width="26" height="26" />
      <span>openRMS <b>account</b></span>
    </a>
    <nav class="flex flex-1 gap-4">
      {#if $session.data?.user}
        {#each nav as n}
          <a
            href={n.href}
            aria-current={page.url.pathname === n.href ? "page" : undefined}
            class="text-muted-foreground aria-[current=page]:text-foreground aria-[current=page]:border-primary border-b-2 border-transparent py-1 no-underline"
          >{n.label}</a>
        {/each}
      {/if}
    </nav>
    {#if $session.data?.user}
      <div class="flex items-center gap-3">
        <span class="font-mono font-bold">{$session.data.user.callsign}</span>
        <Button variant="outline" onclick={signOut}>Sign out</Button>
      </div>
    {/if}
  </div>
</header>

<main class="mx-auto min-h-[70vh] max-w-[900px] px-4">
  {@render children()}
</main>

<footer class="text-muted-foreground mx-auto mt-12 max-w-[900px] border-t px-4 pt-4 pb-8 text-sm">
  One openRMS account signs you in to every openRMS app: the Directory, Rigs, Watch and more. openRMS is open source (AGPL-3.0).
</footer>
