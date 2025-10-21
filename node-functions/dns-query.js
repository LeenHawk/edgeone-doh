// Node Functions version of DoH proxy with ECS injection using dns-packet
// Route: /dns-query (GET with ?dns=... or POST with application/dns-message)
// Reads client IP from context.clientIp or EO-Connecting-IP and injects EDNS CLIENT_SUBNET (RFC 7871)

import * as dnsPacket from 'dns-packet'

const DEFAULTS = {
  UPSTREAM_DOH: 'https://dns.google/dns-query',
  ECS_V4_PREFIX: 24,
  ECS_V6_PREFIX: 56,
  CONNECTING_IP_HEADER: 'EO-Connecting-IP',
}

export async function onRequestGet(context) {
  return handleRequest(context)
}

export async function onRequestPost(context) {
  return handleRequest(context)
}

async function handleRequest({ request, env, clientIp }) {
  const cfg = loadConfig(env)
  const method = request.method.toUpperCase()
  const url = new URL(request.url)

  let dnsWire
  if (method === 'GET') {
    const dnsParam = url.searchParams.get('dns')
    if (!dnsParam) return json({ error: 'missing dns param' }, 400)
    dnsWire = base64urlDecode(dnsParam)
  } else if (method === 'POST') {
    const ct = request.headers.get('content-type') || ''
    if (!ct.startsWith('application/dns-message')) {
      return json({ error: 'unsupported content-type' }, 415)
    }
    dnsWire = new Uint8Array(await request.arrayBuffer())
  } else {
    return new Response('Method Not Allowed', { status: 405 })
  }

  const ip = pickClientIp({ request, clientIp }, cfg.CONNECTING_IP_HEADER)
  const mutated = injectECS(dnsWire, ip, cfg)

  // Always POST upstream to avoid URL length issues
  const upstreamRes = await fetch(cfg.UPSTREAM_DOH, {
    method: 'POST',
    headers: {
      'content-type': 'application/dns-message',
      'accept': 'application/dns-message',
    },
    body: mutated,
  })

  const body = await upstreamRes.arrayBuffer()
  const h = new Headers({
    'content-type': 'application/dns-message',
    'cache-control': 'no-store',
    'access-control-allow-origin': '*',
  })
  return new Response(body, { status: upstreamRes.status, headers: h })
}

function loadConfig(env) {
  return {
    UPSTREAM_DOH: (env && env.UPSTREAM_DOH) || DEFAULTS.UPSTREAM_DOH,
    ECS_V4_PREFIX: env && env.ECS_V4_PREFIX ? Number(env.ECS_V4_PREFIX) : DEFAULTS.ECS_V4_PREFIX,
    ECS_V6_PREFIX: env && env.ECS_V6_PREFIX ? Number(env.ECS_V6_PREFIX) : DEFAULTS.ECS_V6_PREFIX,
    CONNECTING_IP_HEADER: (env && env.CONNECTING_IP_HEADER) || DEFAULTS.CONNECTING_IP_HEADER,
  }
}

function pickClientIp({ request, clientIp }, headerName) {
  // Priority: explicit clientIp from platform -> EO-Connecting-IP header -> x-forwarded-for
  if (clientIp && String(clientIp).trim()) return String(clientIp).trim()
  const h = request.headers
  const byHeader = h.get(headerName) || h.get(headerName.toLowerCase()) || ''
  if (byHeader) return byHeader.split(',')[0].trim()
  const xff = (h.get('x-forwarded-for') || '').split(',')[0].trim()
  return xff
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8', 'access-control-allow-origin': '*' },
  })
}

function base64urlDecode(s) {
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : ''
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

function injectECS(wire, ipStr, cfg) {
  if (!ipStr) return wire
  let pkt
  try {
    pkt = dnsPacket.decode(wire)
  } catch {
    return wire
  }

  // Normalize and detect family
  const isV6 = ipStr.includes(':')
  const family = isV6 ? 2 : 1
  const srcPrefix = isV6 ? cfg.ECS_V6_PREFIX : cfg.ECS_V4_PREFIX

  // Ensure OPT additional record exists
  pkt.additionals = pkt.additionals || []
  let opt = pkt.additionals.find((r) => r.type === 'OPT')
  if (!opt) {
    opt = { type: 'OPT', name: '.', udpPayloadSize: 4096, flags: 0, options: [] }
    pkt.additionals.push(opt)
  } else {
    opt.options = opt.options || []
  }

  // Remove existing ECS options
  opt.options = opt.options.filter((o) => o.code !== 'CLIENT_SUBNET' && o.code !== 8)

  // Add ECS
  opt.options.push({
    code: 'CLIENT_SUBNET',
    family,
    sourcePrefixLength: Number(srcPrefix) | 0,
    scopePrefixLength: 0,
    ip: ipStr,
  })

  try {
    return dnsPacket.encode(pkt)
  } catch {
    return wire
  }
}

