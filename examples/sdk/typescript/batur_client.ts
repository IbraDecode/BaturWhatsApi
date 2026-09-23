// BaturWhatsApi TypeScript SDK (typed thin client over the REST + WS API).
//
// Zero runtime dependencies; runs on Node >=22 via native type stripping:
//
//   node batur_client.ts --url http://127.0.0.1:8080 [--token S] \
//     health|sessions|get <id>|text <sid> <to> <msg>|events|ws [seconds]
//
// The ws subcommand subscribes to /v1/ws and prints live frames; events is
// the SSE fallback.

interface SessionStatus {
  ID: string;
  State: string;
  Account?: string;
  Retries?: number;
  LastOnline?: string;
}

interface WsFrame {
  type: string;
  op?: string;
  ok?: boolean;
  id?: string;
  session?: string;
  error?: string;
  data?: unknown;
}

function usage(): never {
  const u = `usage: node batur_client.ts [--url U] [--token T] health|sessions|get <id>|text <sid> <to> <msg>|events|ws [seconds]`;
  console.error(u);
  process.exit(2);
}

const args = process.argv.slice(2);
function getOpt(name: string, dflt: string): string {
  const i = args.indexOf(name);
  if (i >= 0 && i + 1 < args.length) return args.splice(i, 2)[1];
  return dflt;
}
const BASE = getOpt("--url", "http://127.0.0.1:8080").replace(/\/$/, "");
const TOKEN = getOpt("--token", "");
const cmd = args.shift() || usage();

function headers(extra?: Record<string, string>): Headers {
  const h = new Headers({ "content-type": "application/json", ...(extra || {}) });
  if (TOKEN) h.set("authorization", "Bearer " + TOKEN);
  return h;
}

async function api<T>(method: string, path: string, body?: unknown): Promise<T> {
  const res = await fetch(BASE + path, {
    method,
    headers: headers(),
    body: body === undefined ? undefined : JSON.stringify(body),
  });
  if (!res.ok) throw new Error(`${method} ${path} -> ${res.status}`);
  return res.json() as Promise<T>;
}

async function events(seconds?: number): Promise<void> {
  const res = await fetch(BASE + "/v1/events", {
    headers: headers({ accept: "text/event-stream" }),
  });
  const dec = new TextDecoder();
  let buf = "";
  const stop = seconds
    ? setTimeout(() => { res.body?.cancel(); process.exit(0); }, seconds * 1000)
    : null;
  for await (const chunk of res.body as AsyncIterable<Uint8Array>) {
    buf += dec.decode(chunk, { stream: true });
    let idx: number;
    while ((idx = buf.indexOf("\n\n")) >= 0) {
      const block = buf.slice(0, idx);
      buf = buf.slice(idx + 2);
      const ev: Record<string, string> = {};
      const data: Record<string, unknown> = {};
      for (const line of block.split("\n")) {
        if (line.startsWith("event: ")) ev.event = line.slice(7);
        else if (line.startsWith("data: ")) {
          try { Object.assign(data, JSON.parse(line.slice(6))); } catch (e) { /* keep */ }
        }
      }
      console.log(`[${ev.event}]`, JSON.stringify(data));
    }
  }
  if (stop) clearTimeout(stop);
}

// wsStream: live frames over /v1/ws (global WebSocket, Node >= 22).
function wsStream(seconds?: number): Promise<void> {
  if (typeof WebSocket === "undefined") {
    console.error("# globalThis.WebSocket missing (deno/browser/node>=22?); using SSE");
    return events(seconds);
  }
  const wsURL = BASE.replace(/^http/, "ws") + "/v1/ws";
  return new Promise((resolve) => {
    const ws = new WebSocket(wsURL, {
      headers: TOKEN ? { Authorization: "Bearer " + TOKEN } : {},
    });
    ws.onmessage = (e: MessageEvent) => console.log("[frame]", String(e.data));
    ws.onerror = () => { console.error("ws error"); resolve(); };
    if (seconds) setTimeout(() => { try { ws.close(); } catch (e) { /* noop */ } resolve(); }, seconds * 1000);
  });
}

async function main(): Promise<void> {
  switch (cmd) {
    case "health":
      console.log(JSON.stringify(await api<Record<string, unknown>>("GET", "/v1/health"), null, 2));
      break;
    case "sessions": {
      const { sessions } = await api<{ sessions: SessionStatus[] }>("GET", "/v1/sessions");
      for (const s of sessions) {
        console.log(`${s.ID.padEnd(16)} ${s.State.padEnd(14)} account=${s.Account ?? ""} retries=${s.Retries ?? 0}`);
      }
      break;
    }
    case "get": {
      if (!args[0]) usage();
      console.log(JSON.stringify(await api<SessionStatus>("GET", "/v1/sessions/" + args[0]), null, 2));
      break;
    }
    case "text": {
      const [sid, to, ...rest] = args;
      if (!sid || !to) usage();
      console.log(JSON.stringify(
        await api<{ ok: boolean }>("POST", `/v1/sessions/${sid}/text`, { to, text: rest.join(" ") }),
      ));
      break;
    }
    case "events":
      await events(parseInt(args[0] || "0", 10) || undefined);
      break;
    case "ws":
      await wsStream(parseInt(args[0] || "0", 10) || undefined);
      break;
    default:
      usage();
  }
}

main().catch((e) => { console.error(e); process.exit(1); });