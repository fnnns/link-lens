import http from 'node:http';
import { readFile } from 'node:fs/promises';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
const root = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../extension');
const types = { '.html': 'text/html; charset=utf-8', '.js': 'text/javascript; charset=utf-8', '.css': 'text/css; charset=utf-8', '.json': 'application/json; charset=utf-8', '.png': 'image/png' };
http.createServer(async (request, response) => {
  if (!['GET', 'HEAD'].includes(request.method)) { response.writeHead(405).end(); return; }
  try {
    const url = new URL(request.url, 'http://127.0.0.1');
    const file = path.resolve(root, '.' + decodeURIComponent(url.pathname === '/' ? '/report.html' : url.pathname));
    if (!file.startsWith(root + path.sep)) { response.writeHead(403).end(); return; }
    const data = await readFile(file);
    response.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self' data:; object-src 'none'" });
    response.end(request.method === 'HEAD' ? undefined : data);
  } catch { response.writeHead(404).end('Not found'); }
}).listen(4174, '127.0.0.1', () => { console.log('Demo: http://127.0.0.1:4174/report.html?demo=1'); });
