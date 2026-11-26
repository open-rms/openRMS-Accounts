<script lang="ts">
  // Two-factor sign-in (TOTP + backup codes) and passkeys. Optional for users, required for staff
  // (openRMS-Spec/accounts/identity.md §4b).
  import QRCode from "qrcode";
  import { authClient } from "#lib/auth.ts";
  import { api, type Me } from "#lib/api.ts";
  import { Button } from "#lib/components/ui/button/index.ts";
  import { Input } from "#lib/components/ui/input/index.ts";
  import { Label } from "#lib/components/ui/label/index.ts";
  import { Badge } from "#lib/components/ui/badge/index.ts";
  import * as Card from "#lib/components/ui/card/index.ts";
  import * as Table from "#lib/components/ui/table/index.ts";

  let me = $state<Me | null>(null);
  const refresh = async () => (me = await api.me().catch(() => null));
  $effect(() => {
    refresh();
    loadPasskeys();
  });

  // ---- TOTP
  type Step = "idle" | "password" | "scan" | "codes" | "disable" | "regen";
  let step = $state<Step>("idle"), password = $state(""), code = $state(""), err = $state(""), busy = $state(false);
  let qr = $state(""), secret = $state(""), codes = $state<string[]>([]);

  function start(s: Step) {
    step = s;
    password = code = err = "";
  }

  async function begin(e: Event) {
    e.preventDefault();
    busy = true;
    err = "";
    const { data, error } = await authClient.twoFactor.enable({ password });
    busy = false;
    if (error || !data) return void (err = error?.message ?? "Couldn't start");
    const uri = (data as { totpURI: string }).totpURI;
    secret = new URL(uri).searchParams.get("secret") ?? "";
    codes = (data as { backupCodes: string[] }).backupCodes;
    qr = await QRCode.toDataURL(uri, { margin: 1, width: 200 });
    password = "";
    step = "scan";
  }

  async function confirmCode(e: Event) {
    e.preventDefault();
    busy = true;
    err = "";
    const { error } = await authClient.twoFactor.verifyTotp({ code: code.replace(/\s+/g, "") });
    busy = false;
    if (error) return void (err = error.message ?? "That code didn't work");
    step = "codes";
    await refresh();
  }

  async function disable(e: Event) {
    e.preventDefault();
    busy = true;
    err = "";
    const { error } = await authClient.twoFactor.disable({ password });
    busy = false;
    if (error) return void (err = error.message ?? "Couldn't turn it off");
    start("idle");
    await refresh();
  }

  async function regenerate(e: Event) {
    e.preventDefault();
    busy = true;
    err = "";
    const { data, error } = await authClient.twoFactor.generateBackupCodes({ password });
    busy = false;
    if (error || !data) return void (err = error?.message ?? "Couldn't make new codes");
    codes = (data as { backupCodes: string[] }).backupCodes;
    password = "";
    step = "codes";
  }

  const download = () => {
    const blob = new Blob([`openRMS backup codes for ${me?.user?.callsign ?? ""}\nEach works once.\n\n${codes.join("\n")}\n`], { type: "text/plain" });
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = "openrms-backup-codes.txt";
    a.click();
    URL.revokeObjectURL(a.href);
  };

  // ---- passkeys
  type P = { id: string; name?: string | null; createdAt: string | Date; deviceType?: string };
  let passkeys = $state<P[]>([]), pkName = $state(""), pkErr = $state("");
  async function loadPasskeys() {
    const { data } = await authClient.passkey.listUserPasskeys();
    passkeys = (data ?? []) as P[];
  }
  async function addPasskey(e: Event) {
    e.preventDefault();
    pkErr = "";
    const res = await authClient.passkey.addPasskey({ name: pkName.trim() || undefined });
    if (res?.error) return void (pkErr = res.error.message ?? "Couldn't add the passkey");
    pkName = "";
    await Promise.all([loadPasskeys(), refresh()]);
  }
  async function removePasskey(p: P) {
    if (!window.confirm(`Remove the passkey "${p.name ?? "unnamed"}"? You can't sign in with it afterwards.`)) return;
    const { error } = await authClient.passkey.deletePasskey({ id: p.id });
    if (error) return void (pkErr = error.message ?? "Couldn't remove it");
    await Promise.all([loadPasskeys(), refresh()]);
  }
</script>

<Card.Root class="mb-5" id="security">
  <Card.Header>
    <Card.Title><h2 class="m-0">Sign-in security</h2></Card.Title>
    <Card.Description>A second factor keeps your account safe if your password leaks. Staff need one.</Card.Description>
  </Card.Header>
  <Card.Content class="grid gap-6">
    {#if me?.staffNeedsSecondFactor}
      <p class="border-destructive text-destructive m-0 rounded border p-3">
        Your <b>{me.storedRole ?? "staff"}</b> role is paused until you turn on two-factor sign-in or add a passkey.
      </p>
    {/if}

    <section class="grid gap-3">
      <h3 class="m-0 flex items-center gap-2">
        Authenticator app
        {#if me?.user?.twoFactorEnabled}<Badge variant="open">on</Badge>{:else}<Badge variant="outline">off</Badge>{/if}
      </h3>

      {#if step === "idle"}
        <div class="flex flex-wrap gap-3">
          {#if me?.user?.twoFactorEnabled}
            <Button variant="outline" onclick={() => start("regen")}>New backup codes</Button>
            <Button variant="outline" onclick={() => start("disable")}>Turn off</Button>
          {:else}
            <Button onclick={() => start("password")}>Turn on</Button>
          {/if}
        </div>
      {:else if step === "password" || step === "disable" || step === "regen"}
        <form class="grid max-w-[420px] gap-3" onsubmit={step === "password" ? begin : step === "disable" ? disable : regenerate}>
          <div class="grid gap-1.5">
            <Label for="sp">Your password</Label>
            <Input id="sp" type="password" required autocomplete="current-password" bind:value={password} />
          </div>
          {#if step === "disable"}<p class="text-muted-foreground m-0 text-sm">Your backup codes stop working too.</p>{/if}
          {#if step === "regen"}<p class="text-muted-foreground m-0 text-sm">Your old backup codes stop working.</p>{/if}
          {#if err}<p class="text-destructive m-0">{err}</p>{/if}
          <div class="flex gap-3">
            <Button type="submit" disabled={busy}>{step === "password" ? "Next" : step === "disable" ? "Turn off" : "Make new codes"}</Button>
            <Button type="button" variant="outline" onclick={() => start("idle")}>Cancel</Button>
          </div>
        </form>
      {:else if step === "scan"}
        <form class="grid max-w-[420px] gap-3" onsubmit={confirmCode}>
          <p class="m-0">Scan this with an authenticator app (Aegis, 2FAS, Google Authenticator, 1Password, …).</p>
          <img src={qr} alt="QR code for your authenticator app" width="200" height="200" class="rounded bg-white p-1" />
          <p class="text-muted-foreground m-0 text-sm">Can't scan? Enter this key: <code class="break-all">{secret}</code></p>
          <div class="grid gap-1.5">
            <Label for="tc">The 6-digit code it shows</Label>
            <Input id="tc" required inputmode="numeric" autocomplete="one-time-code" maxlength={7} bind:value={code} />
          </div>
          {#if err}<p class="text-destructive m-0">{err}</p>{/if}
          <div class="flex gap-3">
            <Button type="submit" disabled={busy}>Turn on</Button>
            <Button type="button" variant="outline" onclick={() => start("idle")}>Cancel</Button>
          </div>
        </form>
      {:else if step === "codes"}
        <div class="grid max-w-[420px] gap-3">
          <p class="m-0"><b>Save these backup codes now.</b> Each one signs you in once if you lose your authenticator. You won't see them again.</p>
          <pre class="bg-muted m-0 grid grid-cols-2 gap-1 rounded p-3 font-mono">{#each codes as c}<span>{c}</span>{/each}</pre>
          <div class="flex gap-3">
            <Button variant="outline" onclick={download}>Download</Button>
            <Button variant="outline" onclick={() => navigator.clipboard.writeText(codes.join("\n"))}>Copy</Button>
            <Button onclick={() => start("idle")}>I've saved them</Button>
          </div>
        </div>
      {/if}
    </section>

    <section class="grid gap-3">
      <h3 class="m-0">Passkeys</h3>
      <p class="text-muted-foreground m-0 text-sm">Sign in with your fingerprint, face, screen lock or a security key instead of a password.</p>
      {#if passkeys.length}
        <Table.Root>
          <Table.Body>
            {#each passkeys as p (p.id)}
              <Table.Row>
                <Table.Cell>{p.name ?? "Unnamed passkey"}</Table.Cell>
                <Table.Cell class="text-sm">added {new Date(p.createdAt).toLocaleDateString()}</Table.Cell>
                <Table.Cell class="text-right"><Button variant="outline" size="sm" onclick={() => removePasskey(p)}>Remove</Button></Table.Cell>
              </Table.Row>
            {/each}
          </Table.Body>
        </Table.Root>
      {/if}
      <form class="flex max-w-[420px] flex-wrap items-end gap-3" onsubmit={addPasskey}>
        <div class="grid flex-1 gap-1.5"><Label for="pk">Name (optional)</Label><Input id="pk" placeholder="Phone, YubiKey, …" maxlength={60} bind:value={pkName} /></div>
        <Button type="submit">Add a passkey</Button>
      </form>
      {#if pkErr}<p class="text-destructive m-0">{pkErr}</p>{/if}
    </section>
  </Card.Content>
</Card.Root>
