/**
 * Socket.IO–specific diagnostic rules.
 *
 * These rules look at trace patterns that are characteristic of Socket.IO
 * server behavior, especially when its CORS callback rejects a connection
 * mid-handshake (which surfaces to the client as a generic 5xx from the
 * upstream proxy).
 */

import type { Rule } from "../types.js";

const socketioCorsLikelyRejecting: Rule = {
	id: "socketio.cors-likely-rejecting",
	title: "Socket.IO CORS allow-list likely rejecting this Origin",
	confidence: 0.65,
	match: (trace) => {
		const lib = trace.probes.libraryDetect;
		const polling = trace.probes.polling;
		const ws = trace.probes.wsUpgrade;
		if (lib?.details.library !== "socket.io") return false;
		// Polling worked (so backend is reachable), WS upgrade got 502/503/504,
		// AND we sent an Origin header that the server might be rejecting.
		if (polling?.details.openPacketReceived !== true) return false;
		const status = ws?.details.responseStatus;
		if (status !== 502 && status !== 503 && status !== 504) return false;
		// Only fire if we actually sent an Origin — if we didn't, this isn't the cause.
		return Boolean(ws?.details.originSent);
	},
	cause:
		"Polling works (so the backend is reachable), but the WebSocket upgrade returns 5xx from the proxy. When Socket.IO's CORS callback rejects an Origin mid-handshake, it closes the connection — and the reverse proxy in front of it reports that as 502/503. Your Origin header may not be in the server's allow-list.",
	remediation: [
		"Re-run without --origin: `ws-doctor <url>` (no --origin flag). ws-doctor omits Origin by default; Socket.IO's CORS callback typically accepts requests with no Origin.",
		"Or pass an Origin that matches one of your frontend hostnames: `ws-doctor <url> --origin https://your-frontend.example.com`",
		"Confirm by checking the backend logs for a 'CORS blocked origin' message around the time of the test.",
	],
};

export const socketioRules: Rule[] = [socketioCorsLikelyRejecting];
