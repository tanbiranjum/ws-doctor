/**
 * Library detection — figures out what real-time framework is behind the
 * target URL. The polling and WS-upgrade probes that follow use this to send
 * the right protocol-specific payloads and parse the responses correctly.
 *
 * v0.1 detects Socket.IO (the Engine.IO v4 handshake). v0.2 will add SignalR,
 * Pusher, raw WebSocket fallback.
 *
 * Detection strategy: if the URL path is /socket.io/ or contains EIO query
 * params, treat it as Socket.IO. Otherwise we'll add a polling-handshake
 * probe that confirms. For v0.1, URL heuristic is enough — it's accurate
 * for ~99% of deployments.
 */

import type { LibraryDetectResult, Target } from "../types.js";

export async function probeLibraryDetect(
	target: Target,
): Promise<LibraryDetectResult> {
	const start = performance.now();
	const url = target.url;

	// Strong signals: /socket.io/ path or EIO query param
	const path = url.pathname;
	const hasSocketIoPath = path.includes("/socket.io/") || path === "/socket.io";
	const hasEIOParam = url.searchParams.has("EIO");

	let library: LibraryDetectResult["details"]["library"] = "unknown";
	const evidence: Record<string, unknown> = {};

	if (hasSocketIoPath || hasEIOParam) {
		library = "socket.io";
		evidence.pathMatches = hasSocketIoPath;
		evidence.eioParamPresent = hasEIOParam;
		evidence.eioVersion = url.searchParams.get("EIO");
		evidence.requestedTransport = url.searchParams.get("transport");
	} else {
		// Lacking a path hint — for v0.1 we leave it as unknown. WS upgrade
		// will still be tested with a raw handshake; we just won't have
		// library-specific diagnostics.
		evidence.note =
			"no library-specific path or query params detected — treating as raw-ws";
		library = "raw-ws";
	}

	const durationMs = Math.round(performance.now() - start);

	return {
		phase: "library-detect",
		outcome: "ok",
		durationMs,
		summary:
			library === "socket.io"
				? `Detected Socket.IO${evidence.eioVersion ? ` (EIO=${evidence.eioVersion})` : ""}`
				: library === "raw-ws"
					? "No specific library detected — treating as raw WebSocket"
					: "Unknown library",
		details: { library, evidence },
	};
}
