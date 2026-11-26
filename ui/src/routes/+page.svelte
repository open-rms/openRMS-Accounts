<script lang="ts">
  import { goto } from "$app/navigation";
  import { session } from "#lib/auth.ts";
  $effect(() => {
    if (!$session.isPending) goto($session.data?.user ? "/account" : "/login", { replaceState: true });
  });
</script>
