/**
 * Auth-related rules — the WS handshake succeeds at the protocol level but
 * the server immediately closes because we lack credentials. Distinct from
 * "the server never let us connect."
 */

import type { Rule } from "../types.js";

const closeAfterOpenLikelyAuth: Rule = {
	id: "auth.close-after-open",
	title: "Server closed connection right after open — likely missing auth",
	confidence: 0.5,
	match: (trace) => {
		const ws = trace.probes.wsUpgrade;
		const polling = trace.probes.polling;
		// We got the 101, the polling open packet contains a sid (server is
		// happy at the protocol layer) — if a follow-on probe sees an
		// immediate close, it's auth. v0.1 doesn't have a post-handshake
		// roundtrip probe, so we fire this rule conservatively: 101 received,
		// polling open packet present.
		if (ws?.details.outcomeKind !== "switching-protocols") return false;
		if (!polling?.details.openPacketReceived) return false;
		// This rule is essentially "everything looks good at the network layer
		// — if you're still not getting messages, check auth." Low confidence,
		// but a useful hint.
		return true;
	},
	cause:
		"The WebSocket handshake succeeded and Socket.IO is up at the protocol level. If you're still not receiving application messages, the server may be rejecting unauthenticated connections (Socket.IO's middleware, Engine.IO auth callback, etc.).",
	remediation: [
		"Verify your client sends an auth token. For Socket.IO: `io(URL, { auth: { token } })`.",
		"Check the server logs for a connection-then-disconnect pattern around the time of your test.",
		"If you have an HTTP request that requires the same auth, confirm your token works there first to rule out token issues.",
	],
};

export const authRules: Rule[] = [closeAfterOpenLikelyAuth];
