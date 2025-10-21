// Node Functions version of DoH proxy with ECS injection using dns-packet
// Route: /dns-query (GET with ?dns=... or POST with application/dns-message)
// Reads client IP from context.clientIp or EO-Connecting-IP and injects EDNS CLIENT_SUBNET (RFC 7871)

// No external deps to avoid platform packaging issues

const DEFAULTS = {
  UPSTREAM_DOH: 'https://dns.google/dns-query',
  ECS_V4_PREFIX: 24,
  ECS_V6_PREFIX: 56,
  CONNECTING_IP_HEADER: 'EO-Connecting-IP',
}

export async function onRequest(context) {
  const { request } = context
  const method = (request && request.method || 'GET').toUpperCase()
  if (method === 'HEAD') {
    return new Response(null, { status: 204, headers: { 'cache-control': 'no-store', 'access-control-allow-origin': '*' } })
  }
  if (method === 'GET' || method === 'POST') {
    return handleRequest(context)
  }
  return new Response('Method Not Allowed', { status: 405 })
}

async function handleRequest({ request, env, clientIp }) {
  const cfg = loadConfig(env)
  const method = request.method.toUpperCase()
  let url
  try {
    url = new URL(request.url)
  } catch {
    url = new URL(request.url || '/', getBaseFromHeaders(request && request.headers))
  }

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
  const ecs = buildEcsHeader(ip, cfg)
  if (ecs) {
    h.set('X-ECS', ecs)
    h.set('Access-Control-Expose-Headers', 'X-ECS')
  }
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

function getBaseFromHeaders(headers){
  try{
    const proto=(headers.get('x-forwarded-proto')||'https').split(',')[0].trim()||'https'
    const host=(headers.get('host')||headers.get('x-forwarded-host')||'').split(',')[0].trim()||'localhost'
    return `${proto}://${host}`
  }catch{ return 'https://localhost' }
}

function base64urlDecode(s) {
  const pad = s.length % 4 === 2 ? '==' : s.length % 4 === 3 ? '=' : ''
  const b64 = s.replace(/-/g, '+').replace(/_/g, '/') + pad
  // Node Functions run in Node.js runtime (no atob). Use Buffer when available.
  if (typeof Buffer !== 'undefined') {
    const buf = Buffer.from(b64, 'base64')
    return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength)
  }
  // Fallback to atob in edge-like runtimes
  const bin = atob(b64)
  const out = new Uint8Array(bin.length)
  for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i)
  return out
}

// ===== DNS wire helpers (from Edge version) =====
function readU16(buf, off) { return (buf[off] << 8) | buf[off + 1] }
function writeU16BE(value) { return new Uint8Array([value >> 8, value & 0xff]) }
function readU32(buf, off) { return (buf[off] * 2 ** 24) | (buf[off + 1] << 16) | (buf[off + 2] << 8) | buf[off + 3] }
function skipName(buf, off) {
  let o = off
  while (o < buf.length) {
    const len = buf[o]
    if (len === 0) return o + 1
    if ((len & 0xc0) === 0xc0) return o + 2
    o += 1 + len
  }
  return o
}
function skipQuestion(buf, off) { const endName = skipName(buf, off); return endName + 4 }
function skipRR(buf, off) { const endName = skipName(buf, off); const rdlen = readU16(buf, endName + 8); return endName + 10 + rdlen }
function findSections(buf) {
  const qd = readU16(buf, 4), an = readU16(buf, 6), ns = readU16(buf, 8), ar = readU16(buf, 10)
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
  let len = 0; for (const a of arrays) len += a.length
  const out = new Uint8Array(len); let off = 0
  for (const a of arrays) { out.set(a, off); off += a.length }
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

  const optIdx = addRecs.findIndex((r) => r.type === 41)
  if (optIdx !== -1) {
    const rec = addRecs[optIdx]
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

  // No OPT: append new OPT and bump ARCOUNT
  const arCount = readU16(buf, 10)
  const name = new Uint8Array([0x00])
  const type = writeU16BE(41)
  const udp = writeU16BE(4096)
  const ttl = new Uint8Array([0, 0, 0, 0])
  const rdata = ecsOpt
  const rdlen = writeU16BE(rdata.length)
  const optRecord = concatUint8(name, type, udp, ttl, rdlen, rdata)

  const newBuf = new Uint8Array(buf.length + optRecord.length)
  newBuf.set(buf, 0)
  newBuf.set(optRecord, buf.length)
  const newAR = arCount + 1
  newBuf[10] = (newAR >> 8) & 0xff
  newBuf[11] = newAR & 0xff
  return newBuf
}

function buildEcsHeader(ip, cfg) {
  if (!ip) return ''
  if (ip.includes(':')) {
    const masked = maskIPv6ToPrefix(ip, Number(cfg.ECS_V6_PREFIX) | 0)
    return masked ? `${masked}/${cfg.ECS_V6_PREFIX}` : ''
  } else {
    const masked = maskIPv4ToPrefix(ip, Number(cfg.ECS_V4_PREFIX) | 0)
    return masked ? `${masked}/${cfg.ECS_V4_PREFIX}` : ''
  }
}

function ipv4ToBytes(ip){
  const p=String(ip).split('.').map(x=>parseInt(x,10));
  if(p.length!==4||p.some(n=>Number.isNaN(n)||n<0||n>255))return null;
  return new Uint8Array([p[0],p[1],p[2],p[3]]);
}
function maskIPv4ToPrefix(ip,prefix){
  const b=ipv4ToBytes(ip);if(!b)return'';
  const mask=prefix===0?0:(~0<<(32-prefix))>>>0;
  const ipInt=(b[0]<<24)>>>0|(b[1]<<16)|(b[2]<<8)|b[3];
  const net=ipInt&mask;
  return[(net>>>24)&255,(net>>>16)&255,(net>>>8)&255,net&255].join('.')
}
function ipv6ToBytes(ip){
  const lastColon=ip.lastIndexOf(':');let tailV4=null,_ip=ip;
  if(ip.includes('.')&&lastColon!==-1){
    const v4=ip.slice(lastColon+1);const p=v4.split('.').map(x=>parseInt(x,10));
    if(p.length===4&&p.every(n=>n>=0&&n<=255)){tailV4=p;_ip=ip.slice(0,lastColon)+':0:0'}
  }
  let head=[],tail=[];
  if(_ip.includes('::')){const[h,t]=_ip.split('::');head=h?h.split(':').filter(Boolean):[];tail=t?t.split(':').filter(Boolean):[]}
  else{head=_ip.split(':').filter(Boolean)}
  if(head.length+tail.length>8)return null;
  const zeros=new Array(8-head.length-tail.length).fill('0');
  const full=[...head,...zeros,...tail].slice(0,8);
  if(tailV4){full[6]=((tailV4[0]<<8)|tailV4[1]).toString(16);full[7]=((tailV4[2]<<8)|tailV4[3]).toString(16)}
  const out=new Uint8Array(16);
  for(let i=0;i<8;i++){const v=parseInt(full[i]||'0',16);if(Number.isNaN(v)||v<0||v>0xffff)return null;out[i*2]=(v>>8)&0xff;out[i*2+1]=v&0xff}
  return out
}
function bytesToIpv6(bytes){
  const words=[];for(let i=0;i<16;i+=2)words.push(((bytes[i]<<8)|bytes[i+1]).toString(16));
  let bestStart=-1,bestLen=0,curStart=-1,curLen=0;
  for(let i=0;i<8;i++){
    if(words[i]==='0'){if(curStart===-1){curStart=i;curLen=1}else curLen++;if(curLen>bestLen){bestLen=curLen;bestStart=curStart}}
    else{curStart=-1;curLen=0}
  }
  if(bestLen>1){const left=words.slice(0,bestStart).join(':'),right=words.slice(bestStart+bestLen).join(':');return(left?left:'')+'::'+(right?right:'')}
  return words.map(w=>w.replace(/^0+/,'')||'0').join(':')
}
function maskIPv6ToPrefix(ip,prefix){
  const b=ipv6ToBytes(ip);if(!b)return'';const full=Math.floor(prefix/8),rem=prefix%8;
  for(let i=full+(rem?1:0);i<16;i++)b[i]=0; if(rem){const keepMask=0xff<<(8-rem);b[full]&=keepMask}
  return bytesToIpv6(b)
}
