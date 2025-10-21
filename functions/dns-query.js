// EdgeOne Pages Function for DoH proxy with ECS injection
// Pure Web/Workers APIs; no Node deps.

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

export async function onRequestHead() {
  return new Response(null, {
    status: 204,
    headers: { 'cache-control': 'no-store' },
  })
}

async function handleRequest({ request, env }) {
  const cfg = loadConfig(env)
  const url = new URL(request.url)
  const method = request.method.toUpperCase()

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

  const clientIp = pickClientIp(request.headers, cfg.CONNECTING_IP_HEADER)
  const mutated = injectECS(dnsWire, clientIp, cfg)

  // Always POST to upstream to avoid URL length limits
  const upstreamRes = await fetch(cfg.UPSTREAM_DOH, {
    method: 'POST',
    headers: {
      'content-type': 'application/dns-message',
      'accept': 'application/dns-message',
    },
    body: mutated,
  })

  const body = await upstreamRes.arrayBuffer()
  return new Response(body, {
    status: upstreamRes.status,
    headers: {
      'content-type': 'application/dns-message',
      'cache-control': 'no-store',
    },
  })
}

function loadConfig(env) {
  return {
    UPSTREAM_DOH: (env && env.UPSTREAM_DOH) || DEFAULTS.UPSTREAM_DOH,
    ECS_V4_PREFIX: env && env.ECS_V4_PREFIX ? Number(env.ECS_V4_PREFIX) : DEFAULTS.ECS_V4_PREFIX,
    ECS_V6_PREFIX: env && env.ECS_V6_PREFIX ? Number(env.ECS_V6_PREFIX) : DEFAULTS.ECS_V6_PREFIX,
    CONNECTING_IP_HEADER: (env && env.CONNECTING_IP_HEADER) || DEFAULTS.CONNECTING_IP_HEADER,
  }
}

function pickClientIp(headers, headerName) {
  const h = headerName.toLowerCase()
  return (
    headers.get(h) ||
    headers.get('cf-connecting-ip') ||
    (headers.get('x-forwarded-for') || '').split(',')[0].trim() ||
    ''
  )
}

function json(obj, status = 200) {
  return new Response(JSON.stringify(obj), {
    status,
    headers: { 'content-type': 'application/json; charset=utf-8' },
  })
}

// ================= Base64url =================
function base64urlDecode(s) {
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : ''
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// ================= DNS helpers =================
function readU16(buf, off) {
  return (buf[off] << 8) | buf[off + 1]
}
function writeU16BE(value) {
  return new Uint8Array([value >> 8, value & 0xff])
}
function readU32(buf, off) {
  return (buf[off] * 2 ** 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3]
}

function skipName(buf, off) {
  let o = off
  while (o < buf.length) {
    const len = buf[o]
    if (len === 0) return o + 1
    // compression pointer 0b11xxxxxx
    if ((len & 0xc0) === 0xc0) return o + 2
    o += 1 + len
  }
  return o
}

function skipQuestion(buf, off) {
  const endName = skipName(buf, off)
  return endName + 4 // type + class
}

function skipRR(buf, off) {
  const endName = skipName(buf, off)
  const rdlen = readU16(buf, endName + 8)
  return endName + 10 + rdlen // type(2)+class(2)+ttl(4)+rdlen(2)
}

function findSections(buf) {
  // DNS header
  const qd = readU16(buf, 4)
  const an = readU16(buf, 6)
  const ns = readU16(buf, 8)
  const ar = readU16(buf, 10)
  let off = 12
  for (let i = 0; i < qd; i++) off = skipQuestion(buf, off)
  for (let i = 0; i < an; i++) off = skipRR(buf, off)
  for (let i = 0; i < ns; i++) off = skipRR(buf, off)
  const additionalStart = off
  return { qd, an, ns, ar, additionalStart }
}

function parseAdditionalRecords(buf, arStart, arCount) {
  const recs = []
  let off = arStart
  for (let i = 0; i < arCount; i++) {
    const nameStart = off
    const nameEnd = skipName(buf, off)
    const type = readU16(buf, nameEnd)
    const klass = readU16(buf, nameEnd + 2)
    const ttl = readU32(buf, nameEnd + 4)
    const rdlen = readU16(buf, nameEnd + 8)
    const rdataStart = nameEnd + 10
    const rdataEnd = rdataStart + rdlen
    recs.push({ nameStart, nameEnd, type, klass, ttl, rdlen, rdataStart, rdataEnd })
    off = rdataEnd
  }
  return recs
}

function concatUint8(...arrays) {
  let len = 0
  for (const a of arrays) len += a.length
  const out = new Uint8Array(len)
  let off = 0
  for (const a of arrays) {
    out.set(a, off)
    off += a.length
  }
  return out
}

function buildEcsOption(ipBytes, family, sourcePrefixLength) {
  const addrBytesCount = Math.ceil(sourcePrefixLength / 8)
  const trimmed = new Uint8Array(addrBytesCount)
  for (let i = 0; i < addrBytesCount; i++) trimmed[i] = ipBytes[i] || 0
  const rem = sourcePrefixLength % 8
  if (rem !== 0 && addrBytesCount > 0) {
    const mask = 0xff << (8 - rem)
    trimmed[addrBytesCount - 1] &= mask
  }
  const familyBytes = writeU16BE(family)
  const optData = concatUint8(
    familyBytes,
    new Uint8Array([sourcePrefixLength & 0xff, 0 /* scopePrefixLength */]),
    trimmed,
  )
  const code = writeU16BE(8)
  const len = writeU16BE(optData.length)
  return concatUint8(code, len, optData)
}

function injectECS(buf, clientIp, cfg) {
  if (!clientIp) return buf
  const ip = parseIp(clientIp)
  if (!ip) return buf
  const family = ip.family
  const srcPrefix = family === 1 ? cfg.ECS_V4_PREFIX : cfg.ECS_V6_PREFIX

  const { ar, additionalStart } = findSections(buf)
  const addRecs = parseAdditionalRecords(buf, additionalStart, ar)
  const ecsOpt = buildEcsOption(ip.bytes, family, srcPrefix)

  // If OPT present, replace/append ECS option inside it
  const optIdx = addRecs.findIndex((r) => r.type === 41)
  if (optIdx !== -1) {
    const rec = addRecs[optIdx]

    // Parse existing options and drop ECS (code 8)
    const options = []
    let p = rec.rdataStart
    while (p + 4 <= rec.rdataEnd) {
      const code = readU16(buf, p)
      const len = readU16(buf, p + 2)
      const optStart = p
      const optEnd = p + 4 + len
      if (optEnd > rec.rdataEnd) break
      if (code !== 8) options.push(buf.slice(optStart, optEnd))
      p = optEnd
    }
    const newRdata = concatUint8(...options, ecsOpt)

    const rdlenOffset = rec.nameEnd + 8
    const head = buf.slice(0, rdlenOffset)
    const newRdlen = writeU16BE(newRdata.length)
    const suffix = buf.slice(rec.rdataEnd)
    return concatUint8(head, newRdlen, newRdata, suffix)
  }

  // No OPT: append a new one and bump ARCOUNT
  const qd = readU16(buf, 4)
  const an = readU16(buf, 6)
  const ns = readU16(buf, 8)
  const arCount = readU16(buf, 10)

  const name = new Uint8Array([0x00]) // root label
  const type = writeU16BE(41)
  const udp = writeU16BE(4096)
  const ttl = new Uint8Array([0, 0, 0, 0])
  const rdata = ecsOpt
  const rdlen = writeU16BE(rdata.length)
  const optRecord = concatUint8(name, type, udp, ttl, rdlen, rdata)

  // Update ARCOUNT in header
  const newBuf = new Uint8Array(buf.length + optRecord.length)
  newBuf.set(buf, 0)
  newBuf.set(optRecord, buf.length)
  // Write new ARCOUNT
  const newAR = arCount + 1
  newBuf[10] = (newAR >> 8) & 0xff
  newBuf[11] = newAR & 0xff
  return newBuf
}

// ================= IP parsing =================
function parseIp(str) {
  if (!str) return null
  if (str.includes(':')) {
    const bytes = parseIPv6(str)
    if (!bytes) return null
    return { family: 2, bytes }
  }
  const bytes = parseIPv4(str)
  if (!bytes) return null
  return { family: 1, bytes }
}

function parseIPv4(str) {
  const parts = str.split('.')
  if (parts.length !== 4) return null
  const out = new Uint8Array(4)
  for (let i = 0; i < 4; i++) {
    if (!/^\d+$/.test(parts[i])) return null
    const n = Number(parts[i])
    if (n < 0 || n > 255) return null
    out[i] = n
  }
  return out
}

function parseIPv6(str) {
  // Handle IPv4-embedded suffix
  let main = str
  let v4bytes = null
  const lastColon = str.lastIndexOf(':')
  const lastDot = str.lastIndexOf('.')
  if (lastDot > lastColon) {
    const v4 = str.slice(lastColon + 1)
    v4bytes = parseIPv4(v4)
    if (!v4bytes) return null
    main = str.slice(0, lastColon)
  }
  const parts = main.split('::')
  if (parts.length > 2) return null
  const left = parts[0] ? parts[0].split(':').filter(Boolean) : []
  const right = parts[1] ? parts[1].split(':').filter(Boolean) : []
  const leftVals = left.map(h => (h ? parseInt(h, 16) : 0))
  const rightVals = right.map(h => (h ? parseInt(h, 16) : 0))
  if (leftVals.some(isNaN) || rightVals.some(isNaN)) return null
  const missing = 8 - (leftVals.length + rightVals.length + (v4bytes ? 2 : 0))
  if (missing < 0) return null
  const words = [
    ...leftVals,
    ...Array(missing).fill(0),
    ...rightVals,
  ]
  if (v4bytes) {
    words.pop() // replace the trailing 0 inserted earlier
    words.push((v4bytes[0] << 8) | v4bytes[1])
    words.push((v4bytes[2] << 8) | v4bytes[3])
  }
  if (words.length !== 8) return null
  const out = new Uint8Array(16)
  for (let i = 0; i < 8; i++) {
    const w = words[i]
    out[i * 2] = (w >> 8) & 0xff
    out[i * 2 + 1] = w & 0xff
  }
  return out
}
