// functions/dns-query.js
const GOOGLE_DOH_BINARY = 'https://dns.google/dns-query';
const V4_PREFIX = 24;
const V6_PREFIX = 56;

export async function onRequestGet({ request, clientIp }) {
  const rawUrl = request && request.url ? String(request.url) : '';
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    url = new URL(rawUrl || '/', getBaseFromHeaders(request && request.headers));
  }
  const dnsParam = url.searchParams.get('dns');
  if (!dnsParam) return new Response('missing dns param', { status: 400 });
  const dnsBytes = base64UrlToBytes(dnsParam);
  return proxyWithECS({ request, clientIp }, dnsBytes);
}

export async function onRequestPost({ request, clientIp }) {
  const ct = readHeader(request && request.headers, 'content-type') || '';
  if (!ct.includes('application/dns-message')) {
    return new Response('unsupported content-type', { status: 415 });
  }
  const dnsBytes = new Uint8Array(await request.arrayBuffer());
  return proxyWithECS({ request, clientIp }, dnsBytes);
}

export async function onRequestOptions() {
  const h = new Headers();
  h.set('Access-Control-Allow-Origin', '*');
  h.set('Access-Control-Allow-Methods', 'GET,POST,OPTIONS');
  h.set('Access-Control-Allow-Headers', 'content-type');
  return new Response(null, { status: 204, headers: h });
}

async function proxyWithECS(ctx, dnsBytes) {
  const { request, clientIp } = ctx;
  const ip =
    (clientIp && String(clientIp).trim()) ||
    readHeader(request && request.headers, 'EO-Connecting-IP')?.trim() ||
    readHeader(request && request.headers, 'eo-connecting-ip')?.trim() ||
    '';

  // 构造 ECS option 并注入/更新到 DNS 报文
  const ecsOpt = buildEcsOption(ip, V4_PREFIX, V6_PREFIX);
  const patched = injectEcsIntoDnsMessage(dnsBytes, ecsOpt);

  // 统一用 POST 更稳（规避 GET 414 URI Too Long），并最小化 HTTP 头（Host/Content-Type/Accept）。:contentReference[oaicite:3]{index=3}
  const outHeaders = new Headers();
  outHeaders.set('Accept', 'application/dns-message');
  outHeaders.set('Content-Type', 'application/dns-message');

  const upstream = await fetch(GOOGLE_DOH_BINARY, {
    method: 'POST',
    headers: outHeaders,
    body: patched,
    redirect: 'follow',
  });

  const h = new Headers(upstream.headers);
  // 回显当前注入的 ECS 前缀，便于观测
  if (ecsOpt && ecsOpt.length) {
    const ecsHuman = ecsOptionToHuman(ecsOpt);
    if (ecsHuman) h.set('X-ECS', ecsHuman);
  }
  h.set('Access-Control-Allow-Origin', '*');
  h.set('Access-Control-Expose-Headers', 'X-ECS');
  return new Response(upstream.body, { status: upstream.status, headers: h });
}

/* ---------- ECS 构造 ---------- */
function buildEcsOption(ip, v4Prefix, v6Prefix) {
  if (!ip) return new Uint8Array(0);
  if (ip.includes(':')) {
    const family = 2, prefix = v6Prefix;
    const addr16 = ipv6ToBytes(ip); if (!addr16) return new Uint8Array(0);
    const n = Math.ceil(prefix / 8);
    const addr = addr16.slice(0, n);
    zeroTailBits(addr, prefix);
    return buildEcsOptionBytes(family, prefix, 0, addr);
  } else {
    const family = 1, prefix = v4Prefix;
    const addr4 = ipv4ToBytes(ip); if (!addr4) return new Uint8Array(0);
    const n = Math.ceil(prefix / 8);
    const addr = addr4.slice(0, n);
    zeroTailBits(addr, prefix);
    return buildEcsOptionBytes(family, prefix, 0, addr);
  }
}

function buildEcsOptionBytes(family, sourcePrefix, scopePrefix, addrBytes) {
  const buf = new Uint8Array(4 + addrBytes.length);
  const dv = new DataView(buf.buffer);
  dv.setUint16(0, family);      // FAMILY (1=v4,2=v6)
  dv.setUint8(2, sourcePrefix); // SOURCE PREFIX-LENGTH
  dv.setUint8(3, scopePrefix);  // SCOPE PREFIX-LENGTH (客户端一般置 0)
  buf.set(addrBytes, 4);        // ADDRESS (按前缀清零尾部位)
  return buf;
}
function zeroTailBits(bytes, prefix) {
  const rem = prefix % 8;
  if (rem === 0) return;
  const last = Math.ceil(prefix / 8) - 1;
  const mask = 0xff << (8 - rem);
  bytes[last] &= mask;
}

/* ---------- 在 DNS 报文中注入/更新 OPT(ECS) ---------- */
function injectEcsIntoDnsMessage(src, ecsOptData) {
  if (src.length < 12) return src;
  const dv = new DataView(src.buffer, src.byteOffset, src.byteLength);
  const qd = dv.getUint16(4), an = dv.getUint16(6), ns = dv.getUint16(8);
  let ar = dv.getUint16(10);
  let off = 12;

  // 跳过 Question/Answer/Authority
  for (let i = 0; i < qd; i++) { off = skipName(src, off); off += 4; }
  for (let i = 0; i < an; i++) { off = skipRR(src, off); }
  for (let i = 0; i < ns; i++) { off = skipRR(src, off); }

  // 定位 Additional 的 OPT
  let optPos = -1, optEnd = -1, optUdpSize = 4096, optTtl = 0, consumed = off;
  for (let i = 0; i < ar; i++) {
    const rrStart = consumed;
    const nameEnd = skipName(src, consumed);
    const type = readU16(src, nameEnd);
    const klass = readU16(src, nameEnd + 2);
    const ttl   = readU32(src, nameEnd + 4);
    const rdlen = readU16(src, nameEnd + 8);
    const rrEnd = nameEnd + 10 + rdlen;
    consumed = rrEnd;
    if (type === 41) { optPos = rrStart; optEnd = rrEnd; optUdpSize = klass; optTtl = ttl; break; }
  }

  let newOpt = buildOptWithEcs(src, optPos, optEnd, optUdpSize, optTtl, ecsOptData);
  let out;
  if (optPos >= 0) {
    out = concat3(src.subarray(0, optPos), newOpt, src.subarray(optEnd));
    // ARCOUNT 不变
  } else {
    out = concat3(src, newOpt, new Uint8Array(0));
    new DataView(out.buffer, out.byteOffset, out.byteLength).setUint16(10, ar + 1);
  }
  return out;
}

function buildOptWithEcs(src, optPos, optEnd, udpSize, ttl, ecsOptData) {
  let options = [];
  if (optPos >= 0) {
    const nameEnd = skipName(src, optPos);
    const rdlen = readU16(src, nameEnd + 8);
    let p = nameEnd + 10, end = p + rdlen;
    while (p + 4 <= end) {
      const code = readU16(src, p);
      const len  = readU16(src, p + 2);
      const data = src.subarray(p + 4, p + 4 + len);
      if (code !== 8) options.push({ code, data }); // 去掉旧 ECS
      p += 4 + len;
    }
  }
  if (ecsOptData && ecsOptData.length) options.push({ code: 8, data: ecsOptData });

  let rdataLen = 0; for (const o of options) rdataLen += 4 + o.data.length;
  const buf = new Uint8Array(1 + 2 + 2 + 4 + 2 + rdataLen);
  let w = 0;
  buf[w++] = 0x00;                        // NAME = root
  writeU16(buf, w, 41); w += 2;           // TYPE = OPT
  writeU16(buf, w, udpSize || 4096); w += 2; // CLASS = UDP size
  writeU32(buf, w, ttl || 0); w += 4;     // TTL (extRCODE/VERSION/FLAGS)
  writeU16(buf, w, rdataLen); w += 2;     // RDLEN
  for (const o of options) {
    writeU16(buf, w, o.code); w += 2;
    writeU16(buf, w, o.data.length); w += 2;
    buf.set(o.data, w); w += o.data.length;
  }
  return buf;
}

/* ---------- 小工具 ---------- */
function skipRR(src, off) { off = skipName(src, off); const rdlen = readU16(src, off + 8); return off + 10 + rdlen; }
function skipName(src, off) {
  while (off < src.length) {
    const len = src[off];
    if (len === 0) return off + 1;
    if ((len & 0xC0) === 0xC0) return off + 2; // 压缩指针
    off += 1 + len;
  } return off;
}
function readU16(src, off) { return (src[off] << 8) | src[off + 1]; }
function readU32(src, off) { return (src[off] * 0x1000000) + ((src[off + 1] << 16) | (src[off + 2] << 8) | src[off + 3]); }
function writeU16(dst, off, val) { dst[off] = (val >>> 8) & 0xff; dst[off + 1] = val & 0xff; }
function writeU32(dst, off, val) { dst[off] = (val >>> 24) & 0xff; dst[off + 1] = (val >>> 16) & 0xff; dst[off + 2] = (val >>> 8) & 0xff; dst[off + 3] = val & 0xff; }
function concat3(a, b, c) { const o = new Uint8Array(a.length + b.length + c.length); o.set(a,0); o.set(b,a.length); o.set(c,a.length+b.length); return o; }
function ecsOptionToHuman(ecsOptData) {
  try {
    const dv = new DataView(ecsOptData.buffer, ecsOptData.byteOffset, ecsOptData.byteLength);
    const fam = dv.getUint16(0), src = dv.getUint8(2); const addr = ecsOptData.subarray(4);
    if (fam === 1) { const b = new Uint8Array(4); b.set(addr); return `${b[0]}.${b[1]}.${b[2]}.${b[3]}/${src}`; }
    if (fam === 2) { const b = new Uint8Array(16); b.set(addr); return `${bytesToIpv6(b)}/${src}`; }
  } catch {}
  return '';
}
function base64UrlToBytes(b64url) {
  const b64 = b64url.replace(/-/g, '+').replace(/_/g, '/').padEnd(Math.ceil(b64url.length / 4) * 4, '=');
  if (typeof atob === 'function') {
    const bin = atob(b64);
    const out = new Uint8Array(bin.length);
    for (let i = 0; i < bin.length; i++) out[i] = bin.charCodeAt(i);
    return out;
  }
  // Node.js fallback
  const buf = Buffer.from(b64, 'base64');
  return new Uint8Array(buf.buffer, buf.byteOffset, buf.byteLength);
}
function ipv4ToBytes(ip) {
  const p = ip.split('.').map(x => parseInt(x, 10));
  if (p.length !== 4 || p.some(n => Number.isNaN(n) || n < 0 || n > 255)) return null;
  return new Uint8Array([p[0], p[1], p[2], p[3]]);
}
function ipv6ToBytes(ip) {
  const lastColon = ip.lastIndexOf(':'); let tailV4 = null, _ip = ip;
  if (ip.includes('.') && lastColon !== -1) {
    const v4 = ip.slice(lastColon + 1);
    const p = v4.split('.').map(x => parseInt(x, 10));
    if (p.length === 4 && p.every(n => n >= 0 && n <= 255)) { tailV4 = p; _ip = ip.slice(0, lastColon) + ':0:0'; }
  }
  let head = [], tail = [];
  if (_ip.includes('::')) { const [h, t] = _ip.split('::'); head = h ? h.split(':').filter(Boolean) : []; tail = t ? t.split(':').filter(Boolean) : []; }
  else { head = _ip.split(':').filter(Boolean); }
  if (head.length + tail.length > 8) return null;
  const zeros = new Array(8 - head.length - tail.length).fill('0');
  const full = [...head, ...zeros, ...tail].slice(0, 8);
  if (tailV4) { full[6] = ((tailV4[0]<<8)|tailV4[1]).toString(16); full[7] = ((tailV4[2]<<8)|tailV4[3]).toString(16); }
  const out = new Uint8Array(16);
  for (let i=0;i<8;i++){ const v = parseInt(full[i]||'0',16); if(Number.isNaN(v)||v<0||v>0xffff) return null; out[i*2]=(v>>8)&0xff; out[i*2+1]=v&0xff; }
  return out;
}
function bytesToIpv6(bytes) {
  const words=[]; for(let i=0;i<16;i+=2) words.push(((bytes[i]<<8)|bytes[i+1]).toString(16));
  let bestStart=-1,bestLen=0,curStart=-1,curLen=0;
  for(let i=0;i<8;i++){ if(words[i]==='0'){ if(curStart===-1){curStart=i;curLen=1;}else curLen++; if(curLen>bestLen){bestLen=curLen;bestStart=curStart;} } else {curStart=-1;curLen=0;} }
  if(bestLen>1){ const left=words.slice(0,bestStart).join(':'), right=words.slice(bestStart+bestLen).join(':'); return (left?left:'')+'::'+(right?right:''); }
  return words.map(w=>w.replace(/^0+/,'')||'0').join(':');
}

function getBaseFromHeaders(headers){
  try{
    const proto=(readHeader(headers,'x-forwarded-proto')||'https').split(',')[0].trim()||'https';
    const host=(readHeader(headers,'host')||readHeader(headers,'x-forwarded-host')||'').split(',')[0].trim()||'localhost';
    return `${proto}://${host}`;
  }catch{ return 'https://localhost'; }
}

function readHeader(headers, name){
  if (!headers) return '';
  try{
    if (typeof headers.get === 'function') return headers.get(name) || headers.get(name.toLowerCase()) || '';
    const key = String(name).toLowerCase();
    const v = headers[key];
    if (Array.isArray(v)) return v[0] || '';
    return typeof v === 'string' ? v : '';
  }catch{ return ''; }
}
