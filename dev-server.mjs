import http from 'node:http';
import { onRequestGet as resolveGet } from './node-functions/resolve.js';
import {
  onRequestGet as dnsGet,
  onRequestPost as dnsPost,
  onRequestOptions as dnsOptions,
} from './node-functions/dns-query.js';

const PORT = process.env.PORT ? Number(process.env.PORT) : 8787;

function getClientIp(req) {
  const xf = req.headers['x-forwarded-for'];
  if (typeof xf === 'string' && xf.length) return xf.split(',')[0].trim();
  return (req.socket && req.socket.remoteAddress) || '';
}

function toWebHeaders(nodeHeaders) {
  const h = new Headers();
  for (const [k, v] of Object.entries(nodeHeaders)) {
    if (Array.isArray(v)) h.append(k, v.join(', '));
    else if (typeof v === 'string') h.append(k, v);
  }
  return h;
}

function buildWebRequest(req) {
  const url = `http://localhost:${PORT}${req.url}`;
  const init = { method: req.method, headers: toWebHeaders(req.headers) };
  if (!['GET', 'HEAD'].includes(req.method)) {
    init.body = req; // Node stream, pass-through
    // Node.js fetch requires duplex when body is a stream
    init.duplex = 'half';
  }
  return new Request(url, init);
}

async function sendWebResponse(nodeRes, webRes) {
  nodeRes.statusCode = webRes.status;
  webRes.headers.forEach((v, k) => nodeRes.setHeader(k, v));
  const ab = await webRes.arrayBuffer();
  nodeRes.end(Buffer.from(ab));
}

const server = http.createServer(async (req, res) => {
  try {
    const request = buildWebRequest(req);
    const ctx = { request, clientIp: getClientIp(req), env: process.env };
    const { pathname } = new URL(request.url);

    if (pathname === '/resolve' && req.method === 'GET') {
      const r = await resolveGet(ctx);
      return await sendWebResponse(res, r);
    }
    if (pathname === '/dns-query') {
      if (req.method === 'GET') {
        const r = await dnsGet(ctx);
        return await sendWebResponse(res, r);
      }
      if (req.method === 'POST') {
        const r = await dnsPost(ctx);
        return await sendWebResponse(res, r);
      }
      if (req.method === 'OPTIONS') {
        const r = await dnsOptions(ctx);
        return await sendWebResponse(res, r);
      }
    }
    res.statusCode = 404;
    res.setHeader('content-type', 'text/plain; charset=utf-8');
    res.end('Not Found');
  } catch (e) {
    res.statusCode = 500;
    res.setHeader('content-type', 'text/plain; charset=utf-8');
    res.end('Internal Error: ' + (e && e.stack || e));
  }
});

server.listen(PORT, () => {
  console.log(`Dev server listening on http://localhost:${PORT}`);
});
