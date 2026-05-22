# ws-doctor

> Diagnose WebSocket connection failures across every layer. Tells you **where** your `wss://` is dying and **why**.

Most WebSocket testing tools just confirm that the connection failed. `ws-doctor` walks through every layer — DNS → TLS → HTTP → polling → WebSocket upgrade — and pinpoints which one dropped the connection, with ranked likely causes and concrete remediation for each.

```bash
npx ws-doctor wss://your.app/socket.io/
```

## Install

```bash
# One-off
npx ws-doctor wss://your.app/socket.io/

# Or install globally
npm install -g ws-doctor
ws-doctor wss://your.app/socket.io/
```

Requires Node.js 20+.

## Usage

```bash
ws-doctor <url> [options]

Options:
  -t, --timeout <ms>     per-probe timeout (default: 10000)
  --direct <host:port>   bypass DNS and connect to a specific origin
  --origin <url>         send an Origin header on the WS upgrade (omitted by
                         default; useful when the server requires it or you
                         want to test as a specific frontend)
  -v, --verbose          show full probe details
  --no-color             disable colored output
  -V, --version
  -h, --help
```

### Example output

```
ws-doctor  v0.1.0
Target: wss://stage-api.example.com/socket.io/?EIO=4&transport=websocket

Probes
✓ [dns           ] Resolved 1 address(es) — detected cloudflare    23ms
✓ [tls           ] TLS TLSv1.3 via ALPN=h2                        321ms
✓ [http          ] HTTP 200 cloudflare                            459ms
✓ [library-detect] Detected Socket.IO (EIO=4)                       0ms
✓ [polling       ] Polling handshake OK (sid abc123)              427ms
✗ [ws-upgrade    ] No response in 10000ms (silent hang)         10000ms

Diagnosis
Ranked by rule-declared confidence. Higher = more likely root cause.

1. Cloudflare WebSockets toggle likely disabled (55%)
   → Polling works but the WebSocket upgrade returns no response from a
     Cloudflare-proxied host. This is the textbook symptom of Cloudflare
     not forwarding the upgrade — usually because the per-zone WebSockets
     toggle is off.
   Try:
   • Cloudflare dashboard → select the zone → Network → WebSockets → On.
   • Also confirm Security → Bots → Bot Fight Mode is Off (...)
   • Isolation: temporarily set the DNS record to 'DNS only' (grey cloud) and rerun.
   References:
   • https://developers.cloudflare.com/network/websockets/

2. Possible Bun.build target:'node' bug (if backend is Bun-bundled) (25%)
   → If the backend is running on Bun and bundled with `Bun.build({ target: 'node' })` (...)
   ...
```

## What it checks

| Phase | What it does |
|---|---|
| **DNS** | Resolves A/AAAA records, identifies CDN/proxy provider (Cloudflare, AWS CloudFront, Fastly, etc.) from IP ranges |
| **TLS** | Completes TLS handshake, captures negotiated version, ALPN protocol, certificate SAN list, validates hostname match |
| **HTTP** | GET against root path, captures status, headers (`server`, `cf-ray`, `cf-mitigated`), body classification |
| **Library detection** | Identifies Socket.IO from URL hints (`/socket.io/` path, `EIO=` query param) — more libraries in v0.2+ |
| **Polling** | For Socket.IO targets, performs the Engine.IO polling handshake and parses the open packet |
| **WS upgrade** | Raw TCP/TLS, sends an actual `Upgrade: websocket` request, captures bytes-received, time-to-first-byte, and the outcome class: `101 switching-protocols`, `4xx/5xx rejected`, `silent-hang`, `closed-without-response`, `redirected`, or `tls-error` |

## Diagnoses (v0.1)

Each rule is a self-contained "if this trace fingerprint matches, here's the likely cause":

- `cf.ws-toggle-likely-off` — Cloudflare WS toggle disabled on the proxied zone
- `cf.challenge-blocking-upgrade` — Cloudflare security challenge intercepting the upgrade
- `wrong-host.spa-fallback` — URL points at the frontend SPA, not the backend
- `reverse-proxy.drops-upgrade` — Origin proxy (nginx/Traefik/Caddy) not forwarding the Upgrade header
- `reverse-proxy.https-redirect` — Reverse proxy redirecting the upgrade (WS clients don't follow redirects)
- `reverse-proxy.upstream-unreachable` — 502/503/504 from the proxy (backend container down or unreachable)
- `tls.cert-host-mismatch` — Server cert SAN list doesn't include the target hostname
- `tls.handshake-failed` — TLS handshake failed
- `runtime.bun-bundler-target-node` — Possible [Bun #9882](https://github.com/oven-sh/bun/issues/9882) bug when bundling with `target: "node"`
- `auth.close-after-open` — WS connected but server may be rejecting unauthenticated clients
- `socketio.cors-likely-rejecting` — When testing a Socket.IO target with `--origin`, polling works but WS upgrade gets 5xx → the server's CORS allow-list probably doesn't include your origin

## Contributing a rule

Every rule is a small pure function — easy to add. See `src/rules/` for examples. The pattern:

```ts
import type { Rule } from "../types.js";

export const yourRule: Rule = {
  id: "category.short-id",
  title: "Short human-readable title",
  confidence: 0.6, // 0..1 — your honest estimate
  match: (trace) => {
    // Inspect trace.probes.* and return true if this rule applies
    return trace.probes.wsUpgrade?.details.outcomeKind === "silent-hang"
      && /* other conditions */;
  },
  cause: "One-paragraph explanation of what's wrong",
  remediation: [
    "Concrete actionable step 1",
    "Concrete actionable step 2",
  ],
  references: ["https://docs.example.com/relevant-page"],
};
```

Then add it to `src/rules/index.ts`. Open a PR with a corresponding test in `tests/rules.test.ts` using the `makeTrace` helper.

## Programmatic use

```ts
import { run, allRules } from "ws-doctor";

const { trace, diagnoses } = await run({
  target: parseUrl("wss://api.example.com/socket.io/"),
  timeoutMs: 10_000,
  directOrigin: null,
  verbose: false,
});

for (const d of diagnoses) {
  console.log(d.rule.id, d.rule.cause);
}
```

## Roadmap

- **v0.2** — SignalR, Pusher/Soketi, raw WebSocket support; JSON output mode
- **v0.3** — Bidirectional message roundtrip probe (validates end-to-end after upgrade); idle-timeout test
- **v0.4** — Markdown report output (paste into GitHub issues / Slack)
- **v1.0** — Stable rule registry, plugin loader for custom rule sets

## License

MIT
