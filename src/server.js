import Fastify from 'fastify'
import { request as undiciRequest } from 'undici'
import * as dnsPacket from 'dns-packet'
import ipaddr from 'ipaddr.js'

// Config via env
const PORT = process.env.PORT ? Number(process.env.PORT) : 8787
// Upstream DoH endpoint. Google supports ECS, including embedded ECS in DNS wire message.
const UPSTREAM_DOH = process.env.UPSTREAM_DOH || 'https://dns.google/dns-query'
// Default ECS prefix lengths
const ECS_V4_PREFIX = process.env.ECS_V4_PREFIX ? Number(process.env.ECS_V4_PREFIX) : 24
const ECS_V6_PREFIX = process.env.ECS_V6_PREFIX ? Number(process.env.ECS_V6_PREFIX) : 56
// Header name carrying original client IP from EdgeOne
const CONNECTING_IP_HEADER = process.env.CONNECTING_IP_HEADER || 'EO-Connecting-IP'

const fastify = Fastify({ logger: true })

// health
fastify.get('/healthz', async () => ({ ok: true }))

// Helper: base64url decode to Buffer
function b64urlToBuffer(b64url) {
  const pad = b64url.length % 4 === 2 ? '==' : b64url.length % 4 === 3 ? '=' : ''
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/') + pad
  return Buffer.from(b64, 'base64')
}

// Helper: base64url encode from Buffer
function bufferToB64url(buf) {
  return buf
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/g, '')
}

// Inject or update EDNS Client Subnet (ECS) in a DNS message buffer
function injectECS(dnsWireBuf, clientIpStr) {
  if (!clientIpStr) return dnsWireBuf
  let ip
  try {
    ip = ipaddr.parse(clientIpStr)
  } catch {
    return dnsWireBuf
  }

  const family = ip.kind() === 'ipv6' ? 2 : 1
  const sourcePrefixLength = family === 1 ? ECS_V4_PREFIX : ECS_V6_PREFIX

  // Decode packet
  let packet
  try {
    packet = dnsPacket.decode(dnsWireBuf)
  } catch (e) {
    // If decode fails, pass through unchanged
    return dnsWireBuf
  }

  // Ensure additionals array exists
  packet.additionals = packet.additionals || []

  // Find existing OPT record
  let opt = packet.additionals.find((r) => r.type === 'OPT')
  if (!opt) {
    opt = {
      type: 'OPT',
      name: '.',
      udpPayloadSize: 4096,
      flags: 0,
      options: []
    }
    packet.additionals.push(opt)
  } else {
    opt.options = opt.options || []
  }

  // Remove existing CLIENT_SUBNET if any
  opt.options = opt.options.filter((o) => o.code !== 'CLIENT_SUBNET' && o.code !== 8)

  // Add our CLIENT_SUBNET option
  opt.options.push({
    code: 'CLIENT_SUBNET',
    family,
    sourcePrefixLength,
    scopePrefixLength: 0,
    ip: ip.toString()
  })

  // Re-encode
  return dnsPacket.encode(packet)
}

// Proxy to upstream DoH
async function proxyToUpstream({ method, dnsWireBuf, searchParams, headers }) {
  // Prefer POST to keep semantics and avoid URL length limits.
  if (method === 'GET') {
    // If original was GET with ?dns=, we can also POST
    const res = await undiciRequest(UPSTREAM_DOH, {
      method: 'POST',
      headers: {
        'content-type': 'application/dns-message',
        'accept': 'application/dns-message'
      },
      body: dnsWireBuf
    })
    const body = Buffer.from(await res.body.arrayBuffer())
    return { status: res.statusCode, body, headers: res.headers }
  } else {
    const res = await undiciRequest(UPSTREAM_DOH, {
      method: 'POST',
      headers: {
        'content-type': 'application/dns-message',
        'accept': 'application/dns-message'
      },
      body: dnsWireBuf
    })
    const body = Buffer.from(await res.body.arrayBuffer())
    return { status: res.statusCode, body, headers: res.headers }
  }
}

// DoH GET: /dns-query?dns=BASE64URL(dns wire)
fastify.get('/dns-query', async (req, reply) => {
  const dnsParam = req.query?.dns
  if (!dnsParam) {
    return reply.code(400).send({ error: 'missing dns param' })
  }
  const clientIp = req.headers[CONNECTING_IP_HEADER.toLowerCase()] || req.headers['x-forwarded-for']

  const original = b64urlToBuffer(String(dnsParam))
  const mutated = injectECS(original, Array.isArray(clientIp) ? clientIp[0] : clientIp)

  const upstream = await proxyToUpstream({ method: 'GET', dnsWireBuf: mutated, searchParams: req.query, headers: req.headers })
  reply
    .code(upstream.status)
    .headers({ 'content-type': 'application/dns-message', 'cache-control': 'no-store' })
    .send(upstream.body)
})

// DoH POST: binary body, content-type application/dns-message
fastify.post('/dns-query', async (req, reply) => {
  const ct = req.headers['content-type'] || ''
  if (!ct.startsWith('application/dns-message')) {
    return reply.code(415).send({ error: 'unsupported content-type' })
  }

  const chunks = []
  for await (const chunk of req.raw) chunks.push(chunk)
  const bodyBuf = Buffer.concat(chunks)

  const clientIp = req.headers[CONNECTING_IP_HEADER.toLowerCase()] || req.headers['x-forwarded-for']
  const mutated = injectECS(bodyBuf, Array.isArray(clientIp) ? clientIp[0] : clientIp)

  const upstream = await proxyToUpstream({ method: 'POST', dnsWireBuf: mutated, headers: req.headers })
  reply
    .code(upstream.status)
    .headers({ 'content-type': 'application/dns-message', 'cache-control': 'no-store' })
    .send(upstream.body)
})

fastify.listen({ port: PORT, host: '0.0.0.0' })
  .then(addr => fastify.log.info(`DoH ECS proxy listening on ${addr} -> ${UPSTREAM_DOH}`))
  .catch(err => {
    fastify.log.error(err)
    process.exit(1)
  })

