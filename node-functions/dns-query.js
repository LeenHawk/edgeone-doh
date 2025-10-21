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
