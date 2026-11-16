// The encryption path of each address a browser can open without a warning
// (Certificates page). Mirrors mesh-router-nameserver/docs/names-and-certificates.md:
//
//   dot    <app>.<user>.<zone>   box's Let's Encrypt *.<user>.<zone>; the gateway, when
//                                 in the path, passes the raw TLS through. While the
//                                 box has none, the gateway terminates it with its
//                                 fallback *.<user>.<zone> (ZeroSSL first)
//   apex   <user>.<zone>         like dot while the box holds a trusted certificate,
//                                 else terminated with the gateway's *.<zone>
//   dash   <app>-<user>.<zone>   terminated by the gateway with its *.<zone>,
//                                 re-encrypted to the box with cert0
//   sslip  <app>-<ip>.sslip.io   box's Let's Encrypt certificate (HTTP-01), direct
//
// The hop name (<user>.box.<zone>) is not a browser address: it is the inside leg
// of a name the gateway terminates, signed by the Mesh Router CA, and appears here
// only as that leg.
import type { Certificates, OutsideProbe } from './api'

/** Who holds the key of the certificate that ends this leg, which sets its colour. */
export type LegKind =
  | 'box' // a browser-trusted certificate whose key is on the box
  | 'operator' // a browser-trusted certificate whose key the mesh holds (the gateway)
  | 'mesh' // the Mesh Router CA (cert0): private, only the mesh's machines trust it

export interface Leg {
  kind: LegKind
  ca: string
  detail: string
  /** nodes on this leg that only pass the encrypted connection on */
  through?: string[]
  /** carried inside the WireGuard tunnel */
  tunnel?: boolean
  /** how the far end's certificate is checked on this leg */
  check?: string
}

export interface Node {
  name: string
  /** decrypts the traffic here */
  reads: boolean
  box?: boolean
}

export type Verdict = 'e2e' | 'split' | 'off' | 'broken'

export interface Path {
  form: 'dot' | 'apex' | 'dash' | 'sslip'
  label: string
  host: string
  verdict: Verdict
  verdictText: string
  legs: { leg: Leg; to: Node }[]
  notes: string[]
  seen?: OutsideProbe
}

/** The app whose addresses stand as the example: every box runs it. */
export const exampleApp = 'mesh-console'

/** The CA of a certificate seen from outside, as a short name ("ZeroSSL ECC DV SSL CA 2 (ZeroSSL GmbH)" → "ZeroSSL"). */
export function caName(issuer: string | undefined, fallback: string): string {
  if (!issuer) return fallback
  if (/zerossl/i.test(issuer)) return 'ZeroSSL'
  if (/let'?s\s*encrypt/i.test(issuer)) return "Let's Encrypt"
  return issuer
}

const BOX: Node = { name: 'Your box', reads: true, box: true }
const GATEWAY: Node = { name: 'Mesh gateway', reads: true }

export function buildPaths(d: Certificates): Path[] {
  const user = d.domainName || '<you>'
  const zone = d.serverDomain || '<zone>'
  const domain = d.domain || `${user}.${zone}`
  const z = d.zone
  const r = d.routing
  const zoneLive = z?.state === 'ok' || z?.state === 'overdue'
  const delegated = !!z && z.state !== 'not-delegated'
  const dashSeen = d.outside?.find((o) => o.kind === 'dash')
  const dotSeen = d.outside?.find((o) => o.kind === 'dot')
  const apexSeen = d.outside?.find((o) => o.kind === 'apex')
  // The gateway's own *.<zone> CA, as seen on a name it terminates.
  const gatewayCA = caName(
    dashSeen?.holder === 'gateway' ? dashSeen.issuer : apexSeen?.holder === 'gateway' ? apexSeen.issuer : undefined,
    'Public CA',
  )
  const gatewayZoneLeg: Leg = { kind: 'operator', ca: gatewayCA, detail: `*.${zone} · key on the mesh gateway` }
  const tunnel = r?.gateway.mode === 'tunnel'
  const offline = r?.mode === 'offline'
  const hopName = d.meshCert?.hopName || `${user}.box.${zone}`
  const offlineNote = 'The mesh holds no live route to your box right now, so this address does not answer.'

  const boxLE = (name: string, how: string): Leg => ({
    kind: 'box',
    ca: "Let's Encrypt",
    detail: `${name} · ${how} · key on your box`,
  })
  const meshHop = (name: string, check: string): Leg => ({
    kind: 'mesh',
    ca: 'Mesh Router CA',
    detail: `${name} · cert0, key on your box`,
    tunnel,
    check,
  })
  const gatewayHop = meshHop(hopName, 'The gateway accepts only a Mesh Router CA certificate for this name.')

  // A name the mesh terminates: dash names, and the apex without a box certificate.
  const terminated: Path['legs'] = [
    { leg: gatewayZoneLeg, to: GATEWAY },
    { leg: gatewayHop, to: BOX },
  ]

  const paths: Path[] = []

  // ---- dot ------------------------------------------------------------------
  {
    // The nameservers' answer only means something once they serve the domain.
    const through = delegated && z?.answer === 'gateway' ? [tunnel ? 'Mesh gateway, over WireGuard' : 'Mesh gateway'] : []
    const p: Path = {
      form: 'dot',
      label: 'Dot name',
      host: `${exampleApp}.${domain}`,
      verdict: 'e2e',
      verdictText: 'End to end',
      legs: [{ leg: { ...boxLE(`*.${domain}`, 'DNS-01'), through }, to: BOX }],
      notes: [],
      seen: dotSeen,
    }
    if (!delegated) {
      p.verdict = 'off'
      p.verdictText = 'Not available yet'
      p.notes.push(
        'Your domain is not delegated to the mesh nameservers, so your box cannot obtain this certificate. Shown as it will be.',
      )
    } else if (dotSeen?.holder === 'gateway') {
      // The gateway's fallback *.<domain>: seen from outside, so it is what visitors get now.
      p.legs = [
        {
          leg: {
            kind: 'operator',
            ca: caName(dotSeen.issuer, 'Public CA'),
            detail: `*.${domain} · fallback, key on the mesh gateway`,
          },
          to: GATEWAY,
        },
        { leg: gatewayHop, to: BOX },
      ]
      p.verdict = 'split'
      p.verdictText = 'Decrypted by the mesh gateway (fallback)'
      p.notes.push(
        `Your box has no trusted certificate for this name yet, so the mesh gateway serves its fallback certificate for *.${domain} and re-encrypts the traffic to your box. This stops as soon as your box holds its own: the gateway then only passes the encrypted connection on.`,
      )
    } else if (z?.state === 'expired') {
      p.verdict = 'broken'
      p.verdictText = 'Certificate expired'
    } else if (!zoneLive) {
      p.verdict = 'off'
      p.verdictText = 'Waiting for its certificate'
      p.notes.push('Your box is obtaining its certificate. Shown as it will be.')
    } else if (through.length) {
      p.notes.push(
        `The mesh nameservers send visitors through the mesh gateway. It reads only the name in the handshake and forwards the encrypted connection. It also holds a fallback certificate for *.${domain}, which it uses only while your box has none.`,
      )
    }
    if (offline) p.notes.push(offlineNote)
    paths.push(p)
  }

  // ---- apex -----------------------------------------------------------------
  {
    const p: Path = {
      form: 'apex',
      label: 'Your domain',
      host: domain,
      verdict: 'e2e',
      verdictText: 'End to end',
      legs: [],
      notes: [],
      seen: apexSeen,
    }
    if (zoneLive && z?.apexPassthrough !== false) {
      const through = z?.answer === 'gateway' ? [tunnel ? 'Mesh gateway, over WireGuard' : 'Mesh gateway'] : []
      p.legs = [{ leg: { ...boxLE(domain, 'DNS-01'), through }, to: BOX }]
      p.notes.push(
        `Passed through by policy: the gateway's own *.${zone} also matches this name, so it could decrypt it. It does not while your box holds a trusted certificate.`,
      )
    } else {
      p.legs = terminated
      p.verdict = 'split'
      p.verdictText = 'Decrypted by the mesh gateway'
      p.notes.push(
        delegated
          ? 'Your box has no trusted certificate for it yet, so the gateway terminates it with its own.'
          : 'Until your domain is delegated it works like a dash name.',
      )
    }
    if (offline) p.notes.push(offlineNote)
    paths.push(p)
  }

  // ---- dash -----------------------------------------------------------------
  {
    const p: Path = {
      form: 'dash',
      label: 'Dash name',
      host: `${exampleApp}-${user}.${zone}`,
      verdict: 'split',
      verdictText: 'Decrypted by the mesh gateway',
      legs: terminated,
      notes: ['The mesh gateway reads this traffic, then re-encrypts it to your box.'],
      seen: dashSeen,
    }
    if (offline) p.notes.push(offlineNote)
    paths.push(p)
  }

  // ---- sslip.io -------------------------------------------------------------
  {
    const rows = (d.certs ?? []).filter((c) => c.kind === 'sslip')
    const row = rows.find((c) => c.domain.startsWith(`${exampleApp}-`)) ?? rows.find((c) => c.sources.includes('(root domain)'))
    const host = row?.domain ?? (d.ipDash ? `${d.ipDash}.sslip.io` : '<ip>.sslip.io')
    const p: Path = {
      form: 'sslip',
      label: 'sslip.io',
      host,
      verdict: 'e2e',
      verdictText: 'End to end',
      legs: [{ leg: boxLE(host, 'HTTP-01'), to: BOX }],
      notes: [
        "Straight to your box's public IP, without the mesh. Each sslip.io address gets its own certificate, and every certificate is listed publicly (Certificate Transparency) with your IP in its name.",
      ],
    }
    if (!d.ipDash) {
      p.verdict = 'off'
      p.verdictText = 'Not available'
      p.notes = ['Your box has no public IP: sslip.io needs one, with port 80 open.']
    } else if (row?.status && row.status !== 'letsencrypt') {
      p.verdict = 'broken'
      p.verdictText = 'No trusted certificate'
    }
    if (!d.sslipRoutes) p.notes.push('Apps get no sslip.io address on this box (SSLIP_ROUTES=off): only the box\'s own one.')
    paths.push(p)
  }

  return paths
}
