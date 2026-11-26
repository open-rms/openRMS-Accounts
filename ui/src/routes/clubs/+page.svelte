<script lang="ts">
  import { goto } from "$app/navigation";
  import { session } from "#lib/auth.ts";
  import ClubsCard from "#lib/ClubsCard.svelte";
  $effect(() => {
    if (!$session.isPending && !$session.data?.user) goto("/login?next=/clubs");
  });
</script>

{#if $session.data?.user}
  <h1>Clubs and extra callsigns</h1>
  <ClubsCard myUserId={$session.data.user.id} />
{/if}
