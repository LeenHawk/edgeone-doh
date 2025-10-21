/*
 Compare dns.google resolve JSON vs dns-query wire, with/without ECS
 Domain: cdn.lin.pub
 */
import { request as undiciRequest } from 'undici'
import * as dnsPacket from 'dns-packet'

const DOMAIN = process.env.DOMAIN || 'cdn.lin.pub'
const UPSTREAM_DOH = process.env.UPSTREAM_DOH || 'https://dns.google/dns-query'
const UPSTREAM_RESOLVE = process.env.UPSTREAM_RESOLVE || 'https://dns.google/resolve'

function b64url(buf) {
  return Buffer.from(buf)
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

function buildQuery(name, type) {
  return dnsPacket.encode({
    type: 'query',
    id: Math.floor(Math.random() * 65535),
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type, name }],
  })
}

function buildQueryWithECS(name, type, ip, family, sourcePrefixLength) {
  const opt = {
    type: 'OPT',
    name: '.',
    udpPayloadSize: 4096,
    flags: 0,
    options: [{
      code: 'CLIENT_SUBNET',
      family,
      sourcePrefixLength,
      scopePrefixLength: 0,
      ip,
    }],
  }
  return dnsPacket.encode({
    type: 'query',
    id: Math.floor(Math.random() * 65535),
    flags: dnsPacket.RECURSION_DESIRED,
    questions: [{ type, name }],
    additionals: [opt],
  })
}

function extractIPs(decoded) {
  const out = { A: [], AAAA: [] }
  for (const a of decoded.answers || []) {
    if (a.type === 'A') out.A.push(a.data)
    if (a.type === 'AAAA') out.AAAA.push(a.data)
  }
  return out
}

async function dohGet(base, wire) {
  const url = new URL(base)
  url.searchParams.set('dns', b64url(wire))
  const res = await undiciRequest(url.toString(), {
    method: 'GET',
    headers: { accept: 'application/dns-message' },
  })
  const buf = Buffer.from(await res.body.arrayBuffer())
  return dnsPacket.decode(buf)
}

async function resolveJSON(name, type, ecs) {
  const url = new URL(UPSTREAM_RESOLVE)
  url.searchParams.set('name', name)
  url.searchParams.set('type', type)
  if (ecs) url.searchParams.set('edns_client_subnet', ecs)
  const res = await undiciRequest(url.toString(), { method: 'GET', headers: { accept: 'application/dns-json' } })
  const json = await res.body.json()
  const ips = (json.Answer || [])
    .filter((x) => x.type === (type === 'A' ? 1 : 28))
    .map((x) => x.data)
  return { json, ips }
}

async function main() {
  console.log(`Domain: ${DOMAIN}`)

  // JSON resolve without ECS
  const rA = await resolveJSON(DOMAIN, 'A')
  const rAAAA = await resolveJSON(DOMAIN, 'AAAA')
  console.log('\n/resolve (no ECS) A:', rA.ips)
  console.log('/resolve (no ECS) AAAA:', rAAAA.ips)

  // JSON resolve with ECS
  const rAecs = await resolveJSON(DOMAIN, 'A', '1.2.3.4/24')
  const rAAAAecs = await resolveJSON(DOMAIN, 'AAAA', '2001:db8::1/56')
  console.log('\n/resolve (ECS 1.2.3.4/24) A:', rAecs.ips)
  console.log('/resolve (ECS 2001:db8::1/56) AAAA:', rAAAAecs.ips)

  // /dns-query without ECS
  const qA = buildQuery(DOMAIN, 'A')
  const qAAAA = buildQuery(DOMAIN, 'AAAA')
  const dA = await dohGet(UPSTREAM_DOH, qA)
  const dAAAA = await dohGet(UPSTREAM_DOH, qAAAA)
  const ipNoEcs = { ...extractIPs(dA), ...extractIPs(dAAAA) }
  console.log('\n/dns-query (no ECS) A:', ipNoEcs.A)
  console.log('/dns-query (no ECS) AAAA:', ipNoEcs.AAAA)

  // /dns-query with ECS injected
  const qAecs = buildQueryWithECS(DOMAIN, 'A', '1.2.3.4', 1, 24)
  const qAAAAecs = buildQueryWithECS(DOMAIN, 'AAAA', '2001:db8::1', 2, 56)
  const dAecs = await dohGet(UPSTREAM_DOH, qAecs)
  const dAAAAecs = await dohGet(UPSTREAM_DOH, qAAAAecs)
  const ipWithEcs = { ...extractIPs(dAecs), ...extractIPs(dAAAAecs) }
  console.log('\n/dns-query (ECS 1.2.3.4/24) A:', ipWithEcs.A)
  console.log('/dns-query (ECS 2001:db8::1/56) AAAA:', ipWithEcs.AAAA)

  console.log('\nSummary:')
  console.log(' resolve no-ECS A vs dns-query no-ECS A ->', rA.ips, 'vs', ipNoEcs.A)
  console.log(' resolve ECS A vs dns-query ECS A ->', rAecs.ips, 'vs', ipWithEcs.A)
}

main().catch((e) => {
  console.error(e)
  process.exit(1)
})
