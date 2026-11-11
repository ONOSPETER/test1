// Routes same-origin requests under the configured prefixes (e.g. /api) through the
// post-quantum channel to the critical side. Everything else goes to the normal fetch.
import { compact } from './client.mjs';
import connect from './connect.json';

const prefixes = connect.proxyPrefixes ?? ['/api'];
const original = globalThis.fetch.bind(globalThis);
const matches = (p) => !p.startsWith('/api/compact') && prefixes.some((x) => p === x || p.startsWith(`${x}/`));

globalThis.fetch = async (input, init) => {
  const req = new Request(input, init);
  const url = new URL(req.url, globalThis.location?.href);
  if (url.origin !== globalThis.location?.origin || !matches(url.pathname)) return original(input, init);
  const body = ['GET', 'HEAD'].includes(req.method) ? undefined : new Uint8Array(await req.arrayBuffer());
  const out = await compact.http({ method: req.method, path: url.pathname + url.search, headers: Object.fromEntries(req.headers), body });
  return new Response([204, 205, 304].includes(out.status) ? null : out.body, { status: out.status, headers: out.headers });
};
globalThis.compact = compact;
