#!/usr/bin/env node
// BaturWhatsApi Node.js SDK example (Node 18+, zero dependencies).
//
// Usage:
//   node batur_client.mjs --url http://127.0.0.1:8080 [--token S] health|sessions|get <id>|text <sid> <to> <msg>|events [--seconds N]
'use strict';

const args = process.argv.slice(2);
function getOpt(name, dflt) {
  const i = args.indexOf(name);
  if (i >= 0 && i + 1 < args.length) return args.splice(i, 2)[1];
  return dflt;
}
const URL_ = (getOpt('--url', 'http://127.0.0.1:8080')).replace(/\/$/, '');
const TOKEN = getOpt('--token', null);
const cmd = args.shift();

function headers(extra) {
  const h = { 'content-type': 'application/json', ...(extra || {}) };
  if (TOKEN) h.authorization = 'Bearer ' + TOKEN;
  return h;
}

async function api(method, path, body) {
  const res = await fetch(URL_ + path, {
    method,
    headers: headers(),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}: ${await res.text()}`);
  return res.json();
}

async function events(seconds) {
  const res = await fetch(URL_ + '/v1/events', { headers: headers({ accept: 'text/event-stream' }) });
  const dec = new TextDecoder();
  let buf = '';
  const stop = seconds ? setTimeout(() => { res.body.cancel(); process.exit(0); }, seconds * 1000) : null;
  for await (const chunk of res.body) {
    buf += dec.decode(chunk, { stream: true });
    let idx;
    while ((idx = buf.indexOf('\n\n')) >= 0) {
      const block = buf.slice(0, idx); buf = buf.slice(idx + 2);
      const ev = {}, data = {};
      for (const line of block.split('\n')) {
        if (line.startsWith('event: ')) ev.event = line.slice(7);
        else if (line.startsWith('data: ')) { try { Object.assign(data, JSON.parse(line.slice(6))); } catch {} }
      }
      console.log(`[${ev.event}]`, JSON.stringify(data));
    }
  }
  if (stop) clearTimeout(stop);
}

switch (cmd) {
  case 'health':  console.log(JSON.stringify(await api('GET', '/v1/health'), null, 2)); break;
  case 'sessions':console.table(await api('GET', '/v1/sessions').then(r => r.sessions)); break;
  case 'get':     console.log(JSON.stringify(await api('GET', '/v1/sessions/' + args[0]), null, 2)); break;
  case 'text': {
    const [sid, to, ...rest] = args;
    console.log(JSON.stringify(await api('POST', `/v1/sessions/${sid}/text`, { to, text: rest.join(' ') })));
    break;
  }
  case 'events':  await events(parseInt(args[0] || '0', 10) || null); break;
  default:
    console.error('usage: node batur_client.mjs [--url U] [--token T] health|sessions|get <id>|text <sid> <to> <msg>|events [seconds]');
    process.exit(2);
}
