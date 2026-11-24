<script lang="ts">
  import Card from '../lib/Card.svelte'
  import Pill from '../lib/Pill.svelte'
  import { api, ApiError, type GuardInfo, type GuardStatus, type GuardBan } from '../lib/api'
  import { ago, dateTime } from '../lib/format'

  let info = $state<GuardInfo | null>(null)
  let error = $state('')
  let busy = $state(false)
  let result = $state<{ ok: boolean; message: string; output?: string } | null>(null)

  let lookupIp = $state('')
  let lookup = $state<{ ip: string; bans: GuardBan[] } | null>(null)
  let lookupError = $state('')

  let allowValue = $state('')
  let allowDays = $state(0)

  async function load() {
    try {
      info = await api.get<GuardInfo>('/api/guard')
      error = ''
    } catch (e) {
      error = (e as Error).message
    }
  }
  $effect(() => {
    load()
  })

  const status = $derived<GuardStatus | undefined>(info?.status)

  async function act(path: string, body: Record<string, unknown>, done: string) {
    result = null
    busy = true
    try {
      const res = await api.post<{ message?: string; status?: GuardStatus }>(path, body)
      if (res.status && info) info = { ...info, status: res.status }
      result = { ok: true, message: done }
      if (lookup) await doLookup(lookup.ip)
    } catch (e) {
      const b = e instanceof ApiError ? (e.body as { result?: { output?: string } } | undefined) : undefined
      result = { ok: false, message: (e as Error).message, output: b?.result?.output }
    } finally {
      busy = false
    }
  }

  const unban = (value: string) => act('/api/guard/unban', { value }, `${value} is no longer banned on this box.`)
  const allow = (value: string, days = 0) =>
    act(
      '/api/guard/allow',
      { value, days },
      `${value} is never banned on this box${days > 0 ? ` for ${days} days` : ''}. Its current bans are lifted.`,
    )
  const disallow = (value: string, list: string) =>
    act('/api/guard/disallow', { value, list }, `${value} removed from the allowlist.`)

  async function doLookup(ip: string) {
    lookupError = ''
    try {
      lookup = await api.get<{ ip: string; bans: GuardBan[] }>(`/api/guard/lookup?ip=${encodeURIComponent(ip.trim())}`)
    } catch (e) {
      lookup = null
      lookupError = (e as Error).message
    }
  }

  // Where a ban comes from, in the owner's words.
  const LISTS: Record<string, string> = {
    'nsl-fleet': 'Fleet (reported by several boxes)',
    'nsl-spamhaus-drop': 'Spamhaus DROP',
    'nsl-dshield': 'DShield (SANS ISC)',
    'nsl-feodo': 'abuse.ch Feodo Tracker',
    'nsl-blocklist-de': 'blocklist.de',
  }
  function originLabel(origin: string): string {
    if (origin === 'crowdsec') return 'Detected here'
    if (origin === 'cscli') return 'Manual'
    return LISTS[origin] ?? origin
  }
  const imported = (origin: string) => origin.startsWith('nsl-')

  // "3h59m12s" -> "3h 59m", "170h2m" -> "7d 2h"
  function left(d: string): string {
    const m = d.match(/^(?:(\d+)h)?(?:(\d+)m)?/)
    const h = Number(m?.[1] ?? 0)
    const min = Number(m?.[2] ?? 0)
    if (h >= 48) return `${Math.floor(h / 24)}d ${h % 24}h`
    if (h > 0) return `${h}h ${min}m`
    return `${min}m`
  }

  const importedCounts = $derived(Object.entries(status?.sync?.lastImport?.entries ?? {}).sort((a, b) => b[1] - a[1]))
  const importedTotal = $derived(importedCounts.reduce((n, [, c]) => n + c, 0))
</script>

{#if error && !info}
  <Card><p class="error">{error}</p></Card>
{:else if !info}
  <Card><p class="subtle">Loading… (reading the guard takes a few seconds)</p></Card>
{:else if !info.available}
  <Card title="Protection"><p class="subtle">{info.blocked}</p></Card>
{:else if status}
  <div class="grid">
    <Card title="Protection">
      <div class="row">
        <Pill tone={status.running ? 'ok' : status.enabled ? 'warn' : 'neutral'}>
          {status.running ? 'On' : status.enabled ? 'Not running' : 'Off'}
        </Pill>
      </div>
      {#if status.running}
        <p class="muted small">
          Addresses that attack this box (SSH floods, web scanners, exploit probes) are banned at the firewall, on every
          port, when they connect to it directly. Traffic through the gateway is never cut. People who signed in on this
          box are never banned here.
        </p>
      {:else}
        <p class="muted small">
          The guard is {status.enabled ? 'set to on but not running yet: the next self-check starts it' : 'off on this box'}.
          It is turned on with <span class="mono">MESH_GUARD=on</span> in the mesh <span class="mono">.env</span>.
        </p>
      {/if}
    </Card>

    <Card title="Fleet list">
      {#if !status.import}
        <p class="subtle small">Not imported on this box (<span class="mono">MESH_GUARD_IMPORT=off</span>): local detection only.</p>
      {:else if !status.sync?.lastImport}
        <p class="subtle small">Not imported yet.</p>
      {:else}
        {@const li = status.sync.lastImport}
        <p class="small">
          <strong>{importedTotal.toLocaleString()}</strong> addresses and ranges banned from the fleet list, refreshed
          {ago(li.ok)}.
          {#if li.allowlisted}<span class="subtle">{li.allowlisted} left out: allowed on this box.</span>{/if}
        </p>
        <ul class="sources small">
          {#each importedCounts as [origin, n] (origin)}
            <li><span>{originLabel(origin)}</span> <span class="mono">{n.toLocaleString()}</span></li>
          {/each}
        </ul>
        {#if li.error}<p class="small warn-text">Last refresh failed: {li.error}</p>{/if}
      {/if}
      <p class="subtle small">
        {#if status.report}
          This box shares the addresses it bans (address, attack type, time; nothing else) so the fleet can ban an
          attacker seen by several owners.
          {#if status.sync?.lastReport}Last shared {ago(status.sync.lastReport.ok)}.{/if}
        {:else}
          This box shares nothing (<span class="mono">MESH_GUARD_REPORT=off</span>).
        {/if}
      </p>
    </Card>

    {#if status.running}
      <div class="wide">
        <Card title="Is an address banned?">
          <form
            class="row"
            onsubmit={(e) => {
              e.preventDefault()
              if (lookupIp.trim()) doLookup(lookupIp)
            }}
          >
            <input bind:value={lookupIp} placeholder="203.0.113.7 or 2001:db8::1" aria-label="Address" />
            <button type="submit" disabled={!lookupIp.trim()}>Check</button>
          </form>
          {#if lookupError}<p class="error small">{lookupError}</p>{/if}
          {#if lookup}
            {#if lookup.bans.length === 0}
              <p class="small"><Pill tone="ok">not banned</Pill> <span class="mono">{lookup.ip}</span> can reach this box.</p>
            {:else}
              <p class="small"><Pill tone="bad">banned</Pill> <span class="mono">{lookup.ip}</span></p>
              {@render banTable(lookup.bans)}
              <div class="row">
                <button onclick={() => allow(lookup!.ip)} disabled={busy}>Always allow {lookup.ip}</button>
              </div>
              {#if lookup.bans.some((b) => imported(b.origin))}
                <p class="subtle small">A ban from the fleet list comes back within the hour unless the address is allowed.</p>
              {/if}
            {/if}
          {/if}
        </Card>
      </div>

      <div class="wide">
        <Card title="Banned by this box">
          {#if status.local.length === 0}
            <p class="subtle small">Nothing banned by this box's own detection right now.</p>
          {:else}
            {@render banTable(status.local, true)}
          {/if}
        </Card>
      </div>

      <div class="wide">
        <Card title="Never banned here">
          <p class="muted small">
            Your own allowlist: an address or range here is never banned on this box, by its detection or by the fleet
            list, and its bans are lifted when you add it.
          </p>
          <form
            class="row"
            onsubmit={(e) => {
              e.preventDefault()
              if (allowValue.trim()) allow(allowValue.trim(), allowDays).then(() => (allowValue = ''))
            }}
          >
            <input bind:value={allowValue} placeholder="address or range" aria-label="Address or range" />
            <select bind:value={allowDays} aria-label="For how long">
              <option value={0}>for good</option>
              <option value={7}>7 days</option>
              <option value={30}>30 days</option>
              <option value={90}>90 days</option>
            </select>
            <button type="submit" disabled={busy || !allowValue.trim()}>Allow</button>
          </form>
          {@render allowTable(status.allowlists['nsl-owner'] ?? [], 'nsl-owner', 'Nothing yet.')}

          <h3>Signed in recently</h3>
          <p class="subtle small">Filled on its own: addresses that completed a sign-in on this box, for 90 days after it.</p>
          {@render allowTable(status.allowlists['nsl-sso'] ?? [], 'nsl-sso', 'No sign-in recorded yet.')}
        </Card>
      </div>
    {/if}

    {#if result}
      <div class="wide">
        <p>
          <Pill tone={result.ok ? 'ok' : 'bad'}>{result.ok ? 'done' : 'problem'}</Pill>
          {result.message}
        </p>
        {#if result.output}<pre class="out">{result.output}</pre>{/if}
      </div>
    {/if}

    <p class="wide subtle small">
      Public lists: Spamhaus DROP, DShield (SANS Internet Storm Center), abuse.ch Feodo Tracker, blocklist.de.
    </p>
  </div>
{/if}

{#snippet banTable(bans: GuardBan[], actions = false)}
  <div class="table-wrap">
    <table>
      <thead>
        <tr><th>Address</th><th>Why</th><th>From</th><th>Ends in</th>{#if actions}<th></th>{/if}</tr>
      </thead>
      <tbody>
        {#each bans as b (b.id)}
          <tr>
            <td class="mono">{b.value}</td>
            <td class="small">{b.scenario.replace(/^crowdsecurity\//, '')}</td>
            <td class="small">{originLabel(b.origin)}</td>
            <td class="small">{left(b.duration)}</td>
            {#if actions}
              <td class="acts">
                <button onclick={() => unban(b.value)} disabled={busy}>Unban</button>
                <button onclick={() => allow(b.value)} disabled={busy}>Always allow</button>
              </td>
            {/if}
          </tr>
        {/each}
      </tbody>
    </table>
  </div>
{/snippet}

{#snippet allowTable(entries: { value: string; description: string; expiration: string | null }[], list: string, empty: string)}
  {#if entries.length === 0}
    <p class="subtle small">{empty}</p>
  {:else}
    <div class="table-wrap">
      <table>
        <thead><tr><th>Address</th><th>Until</th><th></th></tr></thead>
        <tbody>
          {#each entries as a (a.value)}
            <tr>
              <td class="mono">{a.value}</td>
              <td class="small">{a.expiration ? dateTime(a.expiration) : 'for good'}</td>
              <td class="acts"><button onclick={() => disallow(a.value, list)} disabled={busy}>Remove</button></td>
            </tr>
          {/each}
        </tbody>
      </table>
    </div>
  {/if}
{/snippet}

<style>
  .grid {
    display: grid;
    grid-template-columns: repeat(2, minmax(0, 1fr));
    gap: 1rem;
  }
  .wide {
    grid-column: 1 / -1;
    min-width: 0;
  }
  @media (max-width: 760px) {
    .grid {
      grid-template-columns: minmax(0, 1fr);
    }
  }
  .row {
    display: flex;
    gap: 0.6rem;
    align-items: center;
    flex-wrap: wrap;
    margin: 0.6rem 0;
  }
  .small {
    font-size: 0.8rem;
  }
  .sources {
    list-style: none;
    padding: 0;
    margin: 0.5rem 0;
    display: grid;
    gap: 0.2rem;
  }
  .sources li {
    display: flex;
    justify-content: space-between;
    gap: 1rem;
  }
  .acts {
    white-space: nowrap;
    text-align: right;
  }
  .acts button {
    padding: 0.1rem 0.5rem;
    font-size: 0.75rem;
  }
  h3 {
    font-size: 0.85rem;
    margin: 1.2rem 0 0.3rem;
  }
  .warn-text {
    color: var(--warn-fg);
  }
  .out {
    background: var(--surface-sunken);
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 0.6rem;
    font-family: var(--font-mono);
    font-size: 0.75rem;
    max-height: 240px;
    overflow: auto;
    white-space: pre-wrap;
  }
</style>
