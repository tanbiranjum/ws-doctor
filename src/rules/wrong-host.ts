/**
 * Wrong-host rules — the URL is pointed at something that isn't the backend.
 *
 * Classic case: hitting your SPA frontend (a static site) instead of your
 * API. The SPA's catch-all route returns index.html with HTTP 200 for every
 * path, including /socket.io/. Polling "succeeds" with HTML, WS upgrade hangs
 * or returns 200.
 */

import type { Rule } from "../types.js";

const spaFallbackOnApiPath: Rule = {
	id: "wrong-host.spa-fallback",
	title: "Target host is the frontend SPA, not the backend",
	confidence: 0.85,
	match: (trace) => {
		const http = trace.probes.http;
		const polling = trace.probes.polling;
		const ws = trace.probes.wsUpgrade;
		if (!http) return false;

		// Telltale: server returns 200 with HTML body for the /socket.io/ path,
		// AND the polling probe couldn't find an Engine.IO open packet.
		const httpSaysHtml = http.details.bodyLooksLike === "html";
		const contentDispoIndex = (
			http.details.headers["content-disposition"] ?? ""
		).toLowerCase().includes('index.html');

		// If polling ran and got HTML instead of an open packet, very strong signal
		const pollingMissed =
			polling?.details.openPacketReceived === false &&
			polling?.outcome === "fail";

		// WS upgrade returning 200 with HTML is also classic SPA-fallback
		const wsGotHtml200 =
			ws?.details.responseStatus === 200 &&
			(ws.details.responseHeaders["content-type"] ?? "").includes("html");

		return (
			(httpSaysHtml && (contentDispoIndex || wsGotHtml200)) ||
			(pollingMissed && httpSaysHtml)
		);
	},
	cause:
		"The URL you tested is serving an HTML page (likely your frontend SPA) for the WebSocket path, not a Socket.IO/WebSocket server. Single-page apps commonly catch-all to index.html for unknown paths.",
	remediation: [
		"Confirm whether this hostname is your frontend (where your React/Vue/etc. app is deployed) or your backend.",
		"If your backend lives at a different subdomain (often api.<your-domain> or stage-api.<your-domain>), retest against that.",
		"Check your VITE_API_BASE_URL / NEXT_PUBLIC_API_URL / similar env vars in the frontend — that's the host the WS should target.",
	],
};

export const wrongHostRules: Rule[] = [spaFallbackOnApiPath];
