// functions/resolve.js
const GOOGLE_DOH_JSON = 'https://dns.google/resolve';
const CF_DOH_JSON = 'https://cloudflare-dns.com/dns-query?ct=application%2Fdns-json';
const V4_PREFIX = 24;
const V6_PREFIX = 56;

export async function onRequestGet({ request, clientIp, env }) {
  const rawUrl = request && request.url ? String(request.url) : '';
  let url;
  try {
    url = new URL(rawUrl);
  } catch {
    url = new URL(rawUrl || '/', getBaseFromHeaders(request && request.headers));
  }
  const ip =
    (clientIp && String(clientIp).trim()) ||
    readHeader(request && request.headers, 'EO-Connecting-IP')?.trim() ||
    readHeader(request && request.headers, 'eo-connecting-ip')?.trim() ||
    '';

  // 生成 edns_client_subnet=addr/prefix
  const ecs = buildEcsParam(ip);
  const upstreams = getJsonUpstreams(env);
  const fwd = new URL(upstreams[0]);
  url.searchParams.forEach((v, k) => fwd.searchParams.set(k, v));
  if (ecs) fwd.searchParams.set('edns_client_subnet', ecs);
  // 备份一个不带 ECS 的 search，供 4xx/5xx 回退使用
  const fwdNoEcs = new URL(upstreams[0]);
  url.searchParams.forEach((v, k) => fwdNoEcs.searchParams.set(k, v));

  const outHeaders = new Headers();
  const accept = readHeader(request && request.headers, 'Accept');
  if (accept && /application\/dns-json/i.test(accept)) outHeaders.set('Accept', accept);
  else outHeaders.set('Accept', 'application/dns-json');

  const offline = (env && env.DEV_OFFLINE) || (typeof process!=='undefined' && process.env && process.env.DEV_OFFLINE);
  if (offline) {
    const qname = url.searchParams.get('name') || '';
    const qtype = parseInt(url.searchParams.get('type') || '1', 10);
    const body = {
      Status: 0, TC: false, RD: true, RA: true, AD: false, CD: false,
      Question: qname ? [{ name: qname, type: qtype }] : [],
      Answer: [],
      Comment: 'DEV_OFFLINE mock',
    };
    const h = new Headers();
    if (ecs) h.set('X-ECS', ecs);
    h.set('Access-Control-Allow-Origin', '*');
    h.set('Access-Control-Expose-Headers', 'X-ECS');
    h.set('content-type', 'application/dns-json');
    return new Response(JSON.stringify(body), { status: 200, headers: h });
  }

  let resp;
  try {
    resp = await fetchWithFallback(upstreams, fwd.search, { method: 'GET', headers: outHeaders, redirect: 'follow' });
  } catch (e) {
    // 带 ECS 失败则回退为不带 ECS 的查询
    resp = await fetchWithFallback(upstreams, fwdNoEcs.search, { method: 'GET', headers: outHeaders, redirect: 'follow' });
  }
  const h = new Headers(resp.headers);
  if (ecs) h.set('X-ECS', ecs);
  h.set('Access-Control-Allow-Origin', '*');
  h.set('Access-Control-Expose-Headers', 'X-ECS');
  h.set('Cache-Control', 'no-store');
  return new Response(resp.body, { status: resp.status, headers: h });
}

function buildEcsParam(ip) {
  if (!ip) return '';
  if (ip.includes(':')) {
    const masked = maskIPv6ToPrefix(ip, V6_PREFIX);
    return masked ? `${masked}/${V6_PREFIX}` : '';
  } else {
    const masked = maskIPv4ToPrefix(ip, V4_PREFIX);
    return masked ? `${masked}/${V4_PREFIX}` : '';
  }
}

/* 简单 IPv4/IPv6 掩码工具 */
function ipv4ToBytes(ip){const p=ip.split('.').map(x=>parseInt(x,10));if(p.length!==4||p.some(n=>Number.isNaN(n)||n<0||n>255))return null;return new Uint8Array([p[0],p[1],p[2],p[3]]);}
function maskIPv4ToPrefix(ip,prefix){const b=ipv4ToBytes(ip);if(!b)return'';const mask=prefix===0?0:(~0<<(32-prefix))>>>0;const ipInt=(b[0]<<24)>>>0|(b[1]<<16)|(b[2]<<8)|b[3];const net=ipInt&mask;return[(net>>>24)&255,(net>>>16)&255,(net>>>8)&255,net&255].join('.');}
function ipv6ToBytes(ip){const lastColon=ip.lastIndexOf(':');let tailV4=null,_ip=ip;if(ip.includes('.')&&lastColon!==-1){const v4=ip.slice(lastColon+1);const p=v4.split('.').map(x=>parseInt(x,10));if(p.length===4&&p.every(n=>n>=0&&n<=255)){tailV4=p;_ip=ip.slice(0,lastColon)+':0:0';}}
let head=[],tail=[];if(_ip.includes('::')){const[h,t]=_ip.split('::');head=h?h.split(':').filter(Boolean):[];tail=t?t.split(':').filter(Boolean):[]}else{head=_ip.split(':').filter(Boolean);}if(head.length+tail.length>8)return null;const zeros=new Array(8-head.length-tail.length).fill('0');const full=[...head,...zeros,...tail].slice(0,8);if(tailV4){full[6]=((tailV4[0]<<8)|tailV4[1]).toString(16);full[7]=((tailV4[2]<<8)|tailV4[3]).toString(16);}const out=new Uint8Array(16);for(let i=0;i<8;i++){const v=parseInt(full[i]||'0',16);if(Number.isNaN(v)||v<0||v>0xffff)return null;out[i*2]=(v>>8)&0xff;out[i*2+1]=v&0xff;}return out;}
function bytesToIpv6(bytes){const words=[];for(let i=0;i<16;i+=2)words.push(((bytes[i]<<8)|bytes[i+1]).toString(16));let bestStart=-1,bestLen=0,curStart=-1,curLen=0;for(let i=0;i<8;i++){if(words[i]==='0'){if(curStart===-1){curStart=i;curLen=1}else curLen++;if(curLen>bestLen){bestLen=curLen;bestStart=curStart}}else{curStart=-1;curLen=0}}if(bestLen>1){const left=words.slice(0,bestStart).join(':'),right=words.slice(bestStart+bestLen).join(':');return(left?left:'')+'::'+(right?right:'')}return words.map(w=>w.replace(/^0+/,'')||'0').join(':');}
function maskIPv6ToPrefix(ip,prefix){const b=ipv6ToBytes(ip);if(!b)return'';const full=Math.floor(prefix/8),rem=prefix%8;for(let i=full+(rem?1:0);i<16;i++)b[i]=0;if(rem){const keepMask=0xff<<(8-rem);b[full]&=keepMask}return bytesToIpv6(b);}

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

function getJsonUpstreams(env){
  const u = [];
  const envVal = (env && env.UPSTREAM_JSON) || (typeof process!=='undefined' && process.env && process.env.UPSTREAM_JSON) || '';
  if (envVal) u.push(envVal);
  // 仅使用明确支持 JSON 的上游
  u.push(GOOGLE_DOH_JSON);
  // u.push(CF_DOH_JSON);
  return Array.from(new Set(u));
}

async function fetchWithFallback(baseList, search, init){
  let lastErr;
  for (const base of baseList){
    try{
      const url = base.includes('?') ? base + '&' + search.replace(/^\?/,'') : base + search;
      const ctrl = new AbortController();
      const to = setTimeout(()=>ctrl.abort(new Error('timeout')), 2000);
      const r = await fetch(url, { ...init, signal: ctrl.signal });
      clearTimeout(to);
      if (r.ok) return r;
      lastErr = new Error(`upstream ${base} status ${r.status}`);
    }catch(e){ lastErr = e; }
  }
  throw lastErr || new Error('all upstreams failed');
}
