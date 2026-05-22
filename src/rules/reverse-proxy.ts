/**
 * Reverse-proxy rules — failure modes that come from the origin's reverse
 * proxy (Traefik, nginx, Caddy, etc.) not handling the WS upgrade correctly.
 *
 * These rules apply when the target is NOT behind a known CDN (so we know
 * the origin proxy is what the request lands on directly), polling works,
 * but the WS upgrade silently dies or returns a partial/empty response.
 */

import type { Rule } from "../types.js";

const originProxyDropsUpgrade: Rule = {
	id: "reverse-proxy.drops-upgrade",
	title: "Origin reverse proxy not forwarding the Upgrade header",
	confidence: 0.4,
	match: (trace) => {
		const dns = trace.probes.dns;
		const polling = trace.probes.polling;
		const ws = trace.probes.wsUpgrade;
		return (
			dns?.details.provider !== "cloudflare" &&
			polling?.details.openPacketReceived === true &&
			(ws?.details.outcomeKind === "silent-hang" ||
				ws?.details.outcomeKind === "closed-without-response")
		);
	},
	cause:
		"Polling reaches the backend through the origin proxy, but the WebSocket upgrade gets no response. Common culprits: nginx without proxy_http_version 1.1 / Upgrade header passthrough, Traefik with a strict redirect middleware applied before WS routing, or an HTTPS-redirect middleware catching the upgrade.",
	remediation: [
		"nginx: ensure `proxy_http_version 1.1;`, `proxy_set_header Upgrade $http_upgrade;`, `proxy_set_header Connection \"upgrade\";` are set for the WS location.",
		"Traefik (Coolify-managed): verify no custom labels override the auto-generated routers. Default Traefik handles WS automatically.",
		"Caddy: ensure `reverse_proxy` is used (it handles WS by default). If using `redir` or `header` directives, confirm they don't run before the upgrade.",
		"Bypass the proxy: SSH to the host and run `docker exec` (or equivalent) to test the backend container directly on its internal port. If WS works there, the proxy is the culprit.",
	],
};

const httpsRedirectKillsWs: Rule = {
	id: "reverse-proxy.https-redirect",
	title: "HTTPS redirect intercepting the WS upgrade",
	confidence: 0.6,
	match: (trace) => {
		const ws = trace.probes.wsUpgrade;
		return ws?.details.outcomeKind === "redirected";
	},
	cause:
		"The server responded with a redirect to the WebSocket upgrade attempt. WS clients do not follow redirects — the upgrade fails.",
	remediation: [
		"Most likely you're connecting via ws:// or http:// to a host that force-redirects to HTTPS. Switch to wss:// (and ensure the WS path is correct).",
		"If you ARE already on wss:// and still seeing this, check your reverse proxy for an over-eager redirect middleware applied to all paths — exclude /socket.io/* or your WS endpoint.",
	],
};

const upstreamUnreachable: Rule = {
	id: "reverse-proxy.upstream-unreachable",
	title: "Reverse proxy can't reach the backend (502/503/504)",
	confidence: 0.8,
	match: (trace) => {
		const ws = trace.probes.wsUpgrade;
		const status = ws?.details.responseStatus;
		if (!status) return false;
		return status === 502 || status === 503 || status === 504;
	},
	cause:
		"The reverse proxy (Traefik / nginx / Coolify) responded but couldn't reach the backend application. 502 = backend connection refused, 503 = backend overloaded or down, 504 = backend timed out responding.",
	remediation: [
		"Check that the backend container/process is actually running.",
		"Check the backend logs for crash loops, OOM kills, or startup failures.",
		"Verify the reverse proxy is configured to forward to the correct internal port.",
		"If you just deployed: the backend may still be starting up — wait 30s and retry.",
	],
};

export const reverseProxyRules: Rule[] = [
	originProxyDropsUpgrade,
	httpsRedirectKillsWs,
	upstreamUnreachable,
];
