<script lang="ts" module>
  // What clicking a grey part does, with the two switches the template ships today
  // (tools/set-routing-mode.sh and tools/set-dns-force.sh).
  export type ActionKind = 'tunnel' | 'auto' | 'dns-gateway' | 'dns-auto'
  export interface Action {
    kind: ActionKind
    title: string
    explain: string
    // A second switch the action can flip too, ticked or not by default.
    also?: { label: string; checked: boolean }
  }
</script>

<script lang="ts">
  import Pill from './Pill.svelte'
  import type { BoxCert, Lane, Mode, Overview, Routing, Trace, TraceStats } from './api'
  import { ago, millis } from './format'

  let {
    routing,
    overview,
    busy,
    onaction,
  }: {
    routing: Routing
    overview: Overview | null
    busy: boolean
    onaction: (a: Action, also: boolean) => void
  } = $props()

  type LaneId = Exclude<Lane, 'unknown'>
  type Entry = 'box' | 'gateway'
  type State = 'observed' | 'inferred' | 'idle' | 'unavailable'

  // The traced names are mesh-console.<domain> and mesh-console-<domain>.
  const domain = $derived(overview?.domain ?? routing.trace?.[0]?.host.replace(/^mesh-console[.-]/, '') ?? '')
  const traces = $derived(routing.trace ?? [])
  // A trace that says nothing about the path (no DNS answer, nothing recognised)
  // falls back to what the registry implies.
  const usable = (t: Trace) => t.lane !== 'unknown' && t.entry !== 'unknown'

  function gatewayLane(m: Mode): LaneId | null {
    return m === 'direct' ? 'gateway-agent' : m === 'tunnel' ? 'gateway-tunnel' : null
  }

  const zoneLive = $derived(!!routing.dns?.delegated && !!routing.dns.live)
  const inZone = (host: string) => host === domain || host.endsWith('.' + domain)

  // What the backend's registry implies for a name. Names in the box's own zone
  // follow the nameserver's answer when the zone is delegated; everything else
  // (the dash names in the server's zone) answers the gateways, which pick the
  // route. The trace is the truth; this is the fallback.
  function inferLane(host: string): LaneId | null {
    const s = routing.state
    if (!s) return null
    const d = routing.dns
    if (inZone(host) && zoneLive && d!.answer === 'direct') return 'box-direct'
    return gatewayLane(s.gateway.mode)
  }
  function inferEntry(lane: LaneId): Entry {
    return lane === 'box-direct' ? 'box' : 'gateway'
  }

  const dnsDirect = $derived(
    !!routing.dns?.editable && routing.dns.force === 'auto' && routing.dns.answer === 'direct',
  )
  const forceEditable = $derived(!!routing.force?.editable)
  const tunnelForced = $derived(routing.force?.mode === 'tunnel')

  function unavailable(id: LaneId): string | undefined {
    const s = routing.state
    const d = routing.dns
    switch (id) {
      case 'box-direct':
        if (!d?.delegated) return 'your zone is not delegated to the mesh nameservers'
        if (!d.live) return 'the delegation is not live yet'
        if (routing.boxCert && routing.boxCert.kind !== 'letsencrypt') return 'the box has no publicly trusted certificate yet'
        return undefined
      case 'gateway-agent':
        return s && !s.hasAgent ? 'no direct route registered (behind NAT, or the backend could not validate it)' : undefined
      case 'gateway-tunnel':
        return s && !s.hasTunnel ? 'no tunnel route registered' : undefined
    }
  }

  const dnsGateway: Action = {
    kind: 'dns-gateway',
    title: 'Answer the gateway',
    explain:
      'Your names will answer the gateway instead of this box, and the gateway picks the route. Browsers follow within a minute.',
  }

  function actionFor(id: LaneId): Action | undefined {
    const d = routing.dns
    switch (id) {
      case 'gateway-tunnel':
        if (!routing.state?.hasTunnel || !forceEditable) return undefined
        if (!tunnelForced)
          return {
            kind: 'tunnel',
            title: 'Force the tunnel',
            explain:
              'Traffic goes through the WireGuard tunnel even when a direct connection is available. It is on trial: it switches back to automatic after 5 minutes unless you keep it.' +
              (dnsDirect
                ? ' Your names answer this box directly, so they only reach the tunnel once they answer the gateway. The trial does not undo that part; the gateway always has a route, so it is safe to leave.'
                : ''),
            also: dnsDirect ? { label: 'Also make your names answer the gateway', checked: true } : undefined,
          }
        // Forced, but the names still answer the box directly.
        return dnsDirect ? { ...dnsGateway, explain: dnsGateway.explain + ' The tunnel is forced, so it will take them.' } : undefined
      case 'gateway-agent':
        if (!routing.state?.hasAgent) return undefined
        if (tunnelForced && forceEditable)
          return {
            kind: 'auto',
            title: 'Back to automatic',
            explain: 'The direct connection wins again: the gateway goes straight to this box’s public IP.',
            also:
              d?.editable && d.force === 'gateway'
                ? { label: 'Also let your names answer this box directly again', checked: false }
                : undefined,
          }
        return dnsDirect ? dnsGateway : undefined
      case 'box-direct':
        return d?.editable && d.force === 'gateway'
          ? {
              kind: 'dns-auto',
              title: 'Answer this box directly',
              explain:
                'Back to automatic: your names answer this box directly when it serves them with a trusted certificate, the gateway otherwise.',
            }
          : undefined
    }
  }

  // ---- the graph -------------------------------------------------------------
  // Columns follow the traffic; rows separate the ways through. The box spans
  // rows 0-2 and every way in arrives on its own row.

  type NodeId = 'in' | 'dns' | 'gateway' | 'agent' | 'tunnel' | 'box' | 'out'
  type EdgeId =
    | 'in-dns'
    | 'dns-box'
    | 'dns-gateway'
    | 'gateway-agent'
    | 'gateway-tunnel'
    | 'agent-box'
    | 'tunnel-box'
    | 'box-out'

  const NODES: { id: NodeId; col: number; row: number; label: string; sub: string }[] = [
    { id: 'in', col: 0, row: 1, label: 'Internet', sub: 'visitors' },
    { id: 'dns', col: 1, row: 1, label: 'DNS', sub: 'your names' },
    { id: 'gateway', col: 2, row: 1, label: 'Gateway', sub: 'mesh edge' },
    { id: 'agent', col: 3, row: 1, label: 'Public IP', sub: 'agent route' },
    { id: 'tunnel', col: 3, row: 2, label: 'Tunnel', sub: 'WireGuard' },
    { id: 'box', col: 4, row: 1, label: 'This box', sub: 'Caddy → apps' },
    { id: 'out', col: 5, row: 1, label: 'Internet', sub: 'outgoing' },
  ]
  // `row` is where the edge arrives on the box (its own lane), else the target's row.
  const EDGES: { id: EdgeId; from: NodeId; to: NodeId; row?: number; label?: string }[] = [
    { id: 'in-dns', from: 'in', to: 'dns' },
    { id: 'dns-box', from: 'dns', to: 'box', row: 0, label: 'answers this box' },
    { id: 'dns-gateway', from: 'dns', to: 'gateway', label: 'answers the gateway' },
    { id: 'gateway-agent', from: 'gateway', to: 'agent' },
    { id: 'gateway-tunnel', from: 'gateway', to: 'tunnel' },
    { id: 'agent-box', from: 'agent', to: 'box', row: 1 },
    { id: 'tunnel-box', from: 'tunnel', to: 'box', row: 2 },
    { id: 'box-out', from: 'box', to: 'out' },
  ]

  function pathEdges(lane: LaneId): EdgeId[] {
    if (lane === 'box-direct') return ['in-dns', 'dns-box']
    const head: EdgeId[] = ['in-dns', 'dns-gateway']
    return lane === 'gateway-agent' ? [...head, 'gateway-agent', 'agent-box'] : [...head, 'gateway-tunnel', 'tunnel-box']
  }

  // One entry per name: the path it took (or, unchecked, the one the registry implies).
  interface HostPath {
    host: string
    state: 'observed' | 'inferred'
    lane: LaneId
    entry: Entry
    edges: EdgeId[]
    trace?: Trace
  }
  const hostPaths = $derived.by((): HostPath[] => {
    const names = traces.length ? traces.map((t) => t.host) : domain ? [domain] : []
    const out: HostPath[] = []
    for (const host of names) {
      const t = traces.find((x) => x.host === host)
      if (t && usable(t)) {
        const lane = t.lane as LaneId
        const entry = t.entry as Entry
        out.push({ host, state: 'observed', lane, entry, edges: pathEdges(lane), trace: t })
        continue
      }
      const lane = inferLane(host)
      if (lane) {
        out.push({ host, state: 'inferred', lane, entry: inferEntry(lane), edges: pathEdges(lane), trace: t })
      }
    }
    return out
  })

  // Why an edge cannot carry traffic, when it cannot.
  const edgeBlocked = $derived.by((): Partial<Record<EdgeId, string>> => {
    const b: Partial<Record<EdgeId, string>> = {}
    const direct = unavailable('box-direct')
    if (direct) b['dns-box'] = direct
    const agent = unavailable('gateway-agent')
    if (agent) b['gateway-agent'] = b['agent-box'] = agent
    const tunnel = unavailable('gateway-tunnel')
    if (tunnel) b['gateway-tunnel'] = b['tunnel-box'] = tunnel
    return b
  })

  const rank: Record<State, number> = { observed: 3, inferred: 2, idle: 1, unavailable: 0 }

  // One diagram per name: the path it took lit, the rest grey.
  interface Graph {
    host: string
    path?: HostPath
    edge: Record<EdgeId, State>
    node: Record<NodeId, State>
    // Clickable grey parts: the hop to switch to, and the lane its action belongs to.
    targets: Partial<Record<NodeId | EdgeId, Action>>
  }

  function graphFor(host: string, hp: HostPath | undefined): Graph {
    const edge = {} as Record<EdgeId, State>
    for (const e of EDGES) edge[e.id] = edgeBlocked[e.id] ? 'unavailable' : 'idle'
    if (hp) for (const id of hp.edges) if (rank[hp.state] > rank[edge[id]]) edge[id] = hp.state
    // The way out is the one the trace itself took.
    edge['box-out'] = hp?.trace?.status ? 'observed' : 'idle'

    const node = {} as Record<NodeId, State>
    for (const n of NODES) {
      const touching = EDGES.filter((e) => e.to === n.id || (n.id === 'in' && e.from === 'in')).map((e) => edge[e.id])
      node[n.id] = touching.length
        ? touching.reduce((a, b) => (rank[b] > rank[a] ? b : a), 'unavailable' as State)
        : 'idle'
    }
    node.box = hp ? hp.state : 'idle'

    const targets: Graph['targets'] = {}
    const lit = (s: State) => s === 'observed' || s === 'inferred'
    const tunnel = actionFor('gateway-tunnel')
    if (tunnel && !lit(node.tunnel) && node.tunnel !== 'unavailable') targets.tunnel = tunnel
    const agent = actionFor('gateway-agent')
    if (agent && !lit(node.agent) && node.agent !== 'unavailable') targets.agent = agent
    if (dnsDirect && !lit(node.gateway)) targets.gateway = dnsGateway
    const box = actionFor('box-direct')
    if (box && !lit(edge['dns-box'])) targets['dns-box'] = box
    return { host, path: hp, edge, node, targets }
  }

  const graphs = $derived.by((): Graph[] => {
    if (hostPaths.length) return hostPaths.map((hp) => graphFor(hp.host, hp))
    return [graphFor(domain, undefined)]
  })
  const anyTargets = $derived(graphs.some((g) => Object.keys(g.targets).length))

  // ---- geometry --------------------------------------------------------------
  // Laid out along a flow axis (a) and a cross axis (c); wide containers flow left
  // to right, narrow ones top to bottom, from the same columns and rows.

  let width = $state(900)
  const vertical = $derived(width < 640)
  const G = $derived(
    vertical
      ? { step: 78, lane: 100, sa: 40, sc: 92, pad: 12 } // sa/sc: node size along/across the flow
      : { step: 140, lane: 54, sa: 104, sc: 40, pad: 12 },
  )
  const node = (id: NodeId) => NODES.find((n) => n.id === id)!
  const A = (col: number) => G.pad + G.sa / 2 + col * G.step
  const C = (row: number) => G.pad + G.sc / 2 + row * G.lane
  const xy = (a: number, c: number) => (vertical ? { x: c, y: a } : { x: a, y: c })
  const viewW = $derived(vertical ? 2 * G.pad + 2 * G.lane + G.sc : 2 * G.pad + 5 * G.step + G.sa)
  const viewH = $derived(vertical ? 2 * G.pad + 5 * G.step + G.sa : 2 * G.pad + 2 * G.lane + G.sc)

  function nodeRect(id: NodeId) {
    const n = node(id)
    if (id === 'box') {
      const p = xy(A(n.col) - G.sa / 2, C(0) - G.sc / 2)
      const along = G.sa
      const across = 2 * G.lane + G.sc
      return vertical ? { ...p, w: across, h: along } : { ...p, w: along, h: across }
    }
    const p = xy(A(n.col) - G.sa / 2, C(n.row) - G.sc / 2)
    return vertical ? { ...p, w: G.sc, h: G.sa } : { ...p, w: G.sa, h: G.sc }
  }

  function edgeGeom(e: (typeof EDGES)[number]) {
    const f = node(e.from)
    const t = node(e.to)
    const sa = A(f.col) + G.sa / 2
    const ec = C(e.row ?? t.row)
    // Fan out of the source's side toward each target, so edges leaving one node
    // do not start from a single point.
    const fan = G.sc / 2 - 7
    const sc = C(f.row) + Math.max(-fan, Math.min(fan, (ec - C(f.row)) * 0.3))
    const ea = A(t.col) - G.sa / 2 - 2
    const gap = G.step - G.sa
    const m = sa + gap
    const p = (a: number, c: number) => {
      const q = xy(a, c)
      return `${q.x},${q.y}`
    }
    const straight = ea - m > 1
    const d = straight
      ? `M${p(sa, sc)} C${p(sa + gap / 2, sc)} ${p(sa + gap / 2, ec)} ${p(m, ec)} L${p(ea, ec)}`
      : `M${p(sa, sc)} C${p(sa + gap / 2, sc)} ${p(sa + gap / 2, ec)} ${p(ea, ec)}`
    const l = straight ? xy((m + ea) / 2, ec) : xy((sa + ea) / 2, (sc + ec) / 2)
    return { d, lx: l.x, ly: l.y }
  }


  // ---- interaction -------------------------------------------------------------

  // The clicked part, and the diagram it was clicked in.
  let selected = $state<{ host: string; id: NodeId | EdgeId } | null>(null)
  let also = $state(false)
  const selectedAction = $derived(
    selected ? graphs.find((g) => g.host === selected!.host)?.targets[selected.id] : undefined,
  )
  const isSel = (g: Graph, id: NodeId | EdgeId) => selected?.host === g.host && selected.id === id

  function pick(g: Graph, id: NodeId | EdgeId) {
    const a = g.targets[id]
    if (!a || busy) return
    selected = isSel(g, id) ? null : { host: g.host, id }
    also = a.also?.checked ?? false
  }
  function key(e: KeyboardEvent, g: Graph, id: NodeId | EdgeId) {
    if (e.key === 'Enter' || e.key === ' ') {
      e.preventDefault()
      pick(g, id)
    }
  }
  function confirm() {
    if (!selectedAction) return
    onaction(selectedAction, also)
    selected = null
  }

  // ---- words -------------------------------------------------------------------

  function pathWords(h: HostPath): string {
    const start = h.entry === 'box' ? 'DNS answers this box' : 'DNS answers the gateway'
    switch (h.lane) {
      case 'box-direct':
        return `${start} → this box`
      case 'gateway-agent':
        return `${start} → gateway → public IP → this box`
      case 'gateway-tunnel':
        return `${start} → gateway → tunnel → this box`
    }
  }

  // Where the trace and the registry disagree. Expected for about a minute after a
  // switch: DNS answers live 30 s, the gateways cache routes too.
  const mismatches = $derived(
    hostPaths
      .filter((h) => h.state === 'observed')
      .map((h) => ({ h, want: inferLane(h.host) }))
      .filter(({ h, want }) => want && want !== h.lane),
  )
  const failed = $derived(traces.filter((t) => !usable(t) || t.error))
  const blockedList = $derived(
    (
      [
        ['Direct from DNS', edgeBlocked['dns-box']],
        ['Public IP', edgeBlocked['gateway-agent']],
        ['Tunnel', edgeBlocked['gateway-tunnel']],
      ] as [string, string | undefined][]
    ).filter(([, why]) => why),
  )

  const laneName: Record<LaneId, string> = {
    'box-direct': 'directly to this box',
    'gateway-agent': 'the gateway, to the public IP',
    'gateway-tunnel': 'the gateway, through the tunnel',
  }

  const certKind: Record<BoxCert['kind'], string> = {
    letsencrypt: 'Let’s Encrypt',
    'mesh-ca': 'Mesh CA',
    other: 'Other issuer',
    unreachable: 'No answer',
  }
  function boxCertTone(c: BoxCert) {
    if (c.kind === 'unreachable' || c.renewal === 'expired') return 'bad'
    if (c.renewal === 'overdue') return 'warn'
    return c.kind === 'letsencrypt' ? 'ok' : c.kind === 'mesh-ca' ? 'info' : 'warn'
  }
  function boxCertExplain(c: BoxCert): string {
    switch (c.kind) {
      case 'letsencrypt':
        return c.method === 'dns-01'
          ? `publicly trusted wildcard (*.${c.domain}), so browsers can reach the box directly`
          : 'publicly trusted certificate for the box domain'
      case 'mesh-ca':
        return 'signed by the mesh CA: only the gateway trusts it'
      case 'other':
        return `issued by ${c.issuer ?? 'an unknown CA'}`
      default:
        return c.error ?? 'Caddy did not answer the handshake'
    }
  }
  // Who answers the TCP handshake, so what the ping measures.
  function pingTarget(t: Trace): string {
    return t.entry === 'box' ? 'this box' : t.entry === 'gateway' ? 'the gateway' : 'the address it reached'
  }
  function errorRate(s: TraceStats): string {
    const all = s.count + s.errors
    return all ? `${((100 * s.errors) / all).toFixed(s.errors && s.errors < all / 100 ? 1 : 0)}%` : '—'
  }

  const ipModeExplain: Record<string, string> = {
    egress: 'the address it connects from',
    interface: 'an address bound on this machine',
  }
</script>

{#snippet nodeBody(g: Graph, id: NodeId)}
  {@const r = nodeRect(id)}
  {@const n = node(id)}
  <rect class="n {g.node[id]}" class:sel={isSel(g, id)} x={r.x} y={r.y} width={r.w} height={r.h} rx="7" />
  <text class="nl {g.node[id]}" x={r.x + r.w / 2} y={r.y + r.h / 2 - 2} text-anchor="middle">{n.label}</text>
  <text class="ns" class:cta={!!g.targets[id]} x={r.x + r.w / 2} y={r.y + r.h / 2 + 11} text-anchor="middle">
    {g.targets[id] ? 'click to use' : n.sub}
  </text>
{/snippet}

{#snippet edgeBody(g: Graph, e: (typeof EDGES)[number])}
  {@const geo = edgeGeom(e)}
  <path class="e {g.edge[e.id]}" class:sel={isSel(g, e.id)} d={geo.d} marker-end="url(#rm-arrow-{g.edge[e.id]})" />
  {#if e.label}
    <text class="el {g.edge[e.id]}" x={geo.lx} y={geo.ly + 4} text-anchor="middle">{e.label}</text>
  {/if}
{/snippet}

<!-- Shared by every diagram below. -->
<svg class="defs" width="0" height="0" aria-hidden="true">
  <defs>
    <pattern id="rm-hatch" width="6" height="6" patternUnits="userSpaceOnUse" patternTransform="rotate(45)">
      <rect width="6" height="6" class="hatch-bg" />
      <line x1="0" y1="0" x2="0" y2="6" class="hatch-line" />
    </pattern>
    {#each ['observed', 'inferred', 'idle', 'unavailable'] as s (s)}
      <marker id="rm-arrow-{s}" viewBox="0 0 10 10" refX="9" refY="5" markerWidth="6" markerHeight="6" orient="auto-start-reverse">
        <path d="M0,0 L10,5 L0,10 z" class="arrowhead {s}" />
      </marker>
    {/each}
  </defs>
</svg>

<div class="wrap" bind:clientWidth={width}>
  {#each graphs as g (g.host)}
    <figure>
      <figcaption>
        <span class="dot {g.path?.state ?? 'neutral'}"></span>
        <span class="mono host">{g.host}</span>
        {#if g.path}
          <span class="small">{pathWords(g.path)}</span>
          {#if g.path.state === 'observed'}
            <span class="subtle small">observed {ago(g.path.trace?.checkedAt)}</span>
          {:else}
            <span class="subtle small">inferred from the routes</span>
          {/if}
        {/if}
      </figcaption>
      {#if g.path?.trace?.timing || g.path?.trace?.latency}
        {@const t = g.path.trace}
        <dl class="stats">
          {#if t.ping}
            <div title="TCP handshake to {pingTarget(t)}, median and 95th percentile over {t.ping.count} probes since {ago(t.ping.since)}">
              <dt>Ping</dt>
              <dd>{millis(t.ping.p50)} <span class="subtle">p95 {millis(t.ping.p95)}</span></dd>
            </div>
          {/if}
          {#if t.latency && t.latency.count}
            <div title="Round trips on an open connection, {t.latency.count} requests since {ago(t.latency.since)}; min {millis(t.latency.min)}, max {millis(t.latency.max)}">
              <dt>Request p50 · p95 · p99</dt>
              <dd>{millis(t.latency.p50)} · {millis(t.latency.p95)} · {millis(t.latency.p99)}</dd>
            </div>
          {/if}
          {#if t.timing}
            <div title="The last probe on a fresh connection: DNS, TCP connect, TLS handshake, then the request until the first byte of the answer">
              <dt>Cold request</dt>
              <dd>
                {millis(t.timing.total)}
                <span class="subtle">
                  = DNS {millis(t.timing.dns)} + TCP {millis(t.timing.connect)} + TLS {millis(t.timing.tls)} + answer {millis(t.timing.firstByte)}
                </span>
              </dd>
            </div>
          {/if}
          {#if t.latency}
            <div title="Requests that got no answer, out of {t.latency.count + t.latency.errors}">
              <dt>Errors</dt>
              <dd>{errorRate(t.latency)} <span class="subtle">of {t.latency.count + t.latency.errors}</span></dd>
            </div>
          {/if}
        </dl>
      {/if}
      <svg
        viewBox="0 0 {viewW} {viewH}"
        width="100%"
        role="img"
        aria-label="How traffic reaches this box for {g.host}: lit arrows are in use, grey ones are not"
      >
        {#each EDGES as e (e.id)}
          {#if g.targets[e.id]}
            <g class="click" role="button" tabindex="0" aria-label={g.targets[e.id]!.title} onclick={() => pick(g, e.id)} onkeydown={(ev) => key(ev, g, e.id)}>
              <title>{g.targets[e.id]!.title}</title>
              {@render edgeBody(g, e)}
            </g>
          {:else}
            <g>
              {#if edgeBlocked[e.id]}<title>Unavailable: {edgeBlocked[e.id]}</title>{/if}
              {@render edgeBody(g, e)}
            </g>
          {/if}
        {/each}

        {#each NODES as n (n.id)}
          {#if g.targets[n.id]}
            <g class="click" role="button" tabindex="0" aria-label={g.targets[n.id]!.title} onclick={() => pick(g, n.id)} onkeydown={(ev) => key(ev, g, n.id)}>
              <title>{g.targets[n.id]!.title}</title>
              {@render nodeBody(g, n.id)}
            </g>
          {:else}
            <g>{@render nodeBody(g, n.id)}</g>
          {/if}
        {/each}
      </svg>

      {#if selectedAction && selected?.host === g.host}
        <div class="confirm">
          <p class="small"><strong>{selectedAction.title}</strong> — {selectedAction.explain}</p>
          {#if selectedAction.also}
            <label class="small"><input type="checkbox" bind:checked={also} /> {selectedAction.also.label}</label>
          {/if}
          <div class="actions">
            <button class="primary" onclick={confirm} disabled={busy}>Confirm</button>
            <button onclick={() => (selected = null)}>Cancel</button>
          </div>
        </div>
      {/if}
    </figure>
  {/each}
</div>

<ul class="paths">
  {#if routing.boxCert}
    <li>
      <span class="dot neutral"></span>
      <span class="small">This box serves</span>
      <Pill tone={boxCertTone(routing.boxCert)}>{certKind[routing.boxCert.kind]}</Pill>
      <span class="subtle small">
        {boxCertExplain(routing.boxCert)}{routing.boxCert.notAfter ? `, expires ${ago(routing.boxCert.notAfter)}` : ''}
      </span>
    </li>
  {/if}
  <li>
    <span class="dot neutral"></span>
    <span class="small grow">
      Outgoing traffic leaves from the box’s own address
      {#if overview?.publicIp}<span class="mono">{overview.publicIp}</span>{/if}
      {#if overview?.publicIpMode}<span class="subtle">({ipModeExplain[overview.publicIpMode] ?? overview.publicIpMode})</span>{/if};
      the tunnel carries incoming traffic only.
    </span>
  </li>
</ul>

{#if failed.length || mismatches.length}
  <ul class="notes small">
    {#each failed as t (t.host)}
      <li>
        <span class="mono">{t.host}</span>:
        {usable(t) ? 'reached, but' : 'could not be checked from the box —'}
        <span class="subtle">{t.error ?? 'no recognisable route'}</span>{usable(t) ? '' : '; showing what the routes imply.'}
      </li>
    {/each}
    {#each mismatches as m (m.h.host)}
      <li>
        <span class="mono">{m.h.host}</span> goes through {laneName[m.h.lane]}, while the routes point at
        {laneName[m.want as LaneId]}. Expected for about a minute after a switch (DNS and the gateways cache their answers).
      </li>
    {/each}
  </ul>
{/if}

<p class="subtle small legend">
  <span class="key observed"></span> observed: requested from this box through public DNS, as a visitor would
  · <span class="key inferred"></span> inferred from the routes
  · <span class="key idle"></span> not in use{anyTargets ? ' (click a highlighted grey part to switch to it)' : ''}
  {#if blockedList.length}
    · <span class="key unavailable"></span> unavailable: {blockedList.map(([what, why]) => `${what.toLowerCase()} — ${why}`).join('; ')}
  {/if}
</p>

<style>
  .wrap {
    width: 100%;
    min-width: 0;
  }
  svg {
    display: block;
    max-width: 980px;
    margin: 0 auto;
    font-family: var(--font-sans);
  }
  svg.defs {
    position: absolute;
    overflow: hidden;
  }
  figure {
    margin: 0;
  }
  figure + figure {
    margin-top: 1rem;
    padding-top: 0.75rem;
    border-top: 1px solid var(--border);
  }
  .stats {
    display: flex;
    flex-wrap: wrap;
    gap: 0.4rem 1.4rem;
    margin: 0 0 0.5rem;
    font-size: 0.8rem;
  }
  .stats div {
    min-width: 0;
  }
  .stats dt {
    font-size: 0.7rem;
    color: var(--text-subtle);
  }
  .stats dd {
    margin: 0;
    font-variant-numeric: tabular-nums;
    overflow-wrap: anywhere;
  }
  figcaption {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.3rem 0.5rem;
    margin-bottom: 0.4rem;
    min-width: 0;
  }
  .n {
    stroke-width: 1.5;
  }
  .n.observed {
    fill: var(--ok-bg);
    stroke: var(--ok-fg);
  }
  .n.inferred {
    fill: var(--info-bg);
    stroke: var(--info-fg);
    stroke-dasharray: 5 3;
  }
  .n.idle {
    fill: var(--surface);
    stroke: var(--border-strong);
  }
  .n.unavailable {
    fill: url(#rm-hatch);
    stroke: var(--border-strong);
    stroke-dasharray: 3 3;
  }
  .hatch-bg {
    fill: var(--surface-sunken);
  }
  .hatch-line {
    stroke: var(--border);
    stroke-width: 2;
  }
  .nl {
    font-size: 12px;
    font-weight: 600;
    fill: var(--text);
  }
  .nl.idle,
  .nl.unavailable {
    fill: var(--text-subtle);
  }
  .ns {
    font-size: 10px;
    fill: var(--text-subtle);
  }
  .e {
    fill: none;
  }
  .e.observed {
    stroke: var(--ok-fg);
    stroke-width: 2.5;
  }
  .e.inferred {
    stroke: var(--info-fg);
    stroke-width: 2;
    stroke-dasharray: 6 4;
  }
  .e.idle {
    stroke: var(--border-strong);
    stroke-width: 1.5;
  }
  .e.unavailable {
    stroke: var(--border-strong);
    stroke-width: 1.5;
    stroke-dasharray: 2 4;
    opacity: 0.7;
  }
  .arrowhead.observed {
    fill: var(--ok-fg);
  }
  .arrowhead.inferred {
    fill: var(--info-fg);
  }
  .arrowhead.idle,
  .arrowhead.unavailable {
    fill: var(--border-strong);
  }
  .el {
    font-size: 10.5px;
    fill: var(--text-muted);
    paint-order: stroke;
    stroke: var(--surface);
    stroke-width: 4px;
    stroke-linejoin: round;
  }
  .el.observed {
    fill: var(--ok-fg);
    font-weight: 600;
  }
  .el.idle,
  .el.unavailable {
    fill: var(--text-subtle);
  }
  .click {
    cursor: pointer;
    outline: none;
  }
  .ns.cta {
    fill: var(--primary);
  }
  .click:hover .n,
  .click:focus-visible .n,
  .n.sel {
    stroke: var(--primary);
    stroke-width: 2.5;
    stroke-dasharray: none;
  }
  .click:hover .e,
  .click:focus-visible .e,
  .e.sel {
    stroke: var(--primary);
    stroke-width: 2.5;
    stroke-dasharray: none;
  }
  .paths {
    list-style: none;
    padding: 0;
    margin: 0.6rem 0 0;
    display: grid;
    gap: 0.35rem;
  }
  .paths li {
    display: flex;
    flex-wrap: wrap;
    align-items: center;
    gap: 0.3rem 0.5rem;
    min-width: 0;
  }
  .grow {
    flex: 1 1 12rem;
    min-width: 0;
  }
  .host {
    font-size: 0.78rem;
    overflow-wrap: anywhere;
  }
  .dot,
  .key {
    display: inline-block;
    width: 0.6rem;
    height: 0.6rem;
    border-radius: 50%;
    flex: none;
  }
  .key {
    width: 1.1rem;
    height: 0;
    border-radius: 0;
    vertical-align: middle;
  }
  .dot.observed {
    background: var(--ok-fg);
  }
  .dot.inferred {
    background: var(--info-fg);
  }
  .dot.neutral {
    background: var(--border-strong);
  }
  .key.observed {
    border-top: 2.5px solid var(--ok-fg);
  }
  .key.inferred {
    border-top: 2px dashed var(--info-fg);
  }
  .key.idle {
    border-top: 1.5px solid var(--border-strong);
  }
  .key.unavailable {
    border-top: 1.5px dotted var(--border-strong);
  }
  .mono {
    font-family: var(--font-mono);
  }
  .small {
    font-size: 0.8rem;
  }
  .confirm {
    margin-top: 0.75rem;
    padding: 0.7rem;
    border: 1px solid var(--primary);
    border-radius: 8px;
  }
  .confirm p {
    margin: 0 0 0.5rem;
  }
  .confirm label {
    display: flex;
    gap: 0.4rem;
    align-items: center;
    margin-bottom: 0.5rem;
  }
  .actions {
    display: flex;
    gap: 0.6rem;
  }
  .notes {
    margin: 0.6rem 0 0;
    padding-left: 1.1rem;
    color: var(--warn-fg);
  }
  .notes li + li {
    margin-top: 0.25rem;
  }
  .legend {
    margin: 0.6rem 0 0;
    line-height: 1.6;
  }
</style>
