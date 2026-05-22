/**
 * Polling probe — for libraries that have an HTTP polling fallback (Socket.IO
 * does, with Engine.IO), this hits the polling endpoint and reports whether
 * the protocol-specific handshake response came back.
 *
 * Critical for the most common diagnostic split: "polling works, WS hangs."
 * If polling fails too, the problem is more fundamental (DNS, routing,
 * backend down) — not specific to WebSocket upgrade handling.
 */

import { Agent, request } from "undici";
import type {
	LibraryDetectResult,
	PollingResult,
	Target,
} from "../types.js";

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_BODY = 4096;

interface ProbeArgs {
	target: Target;
	libraryDetect: LibraryDetectResult;
	timeoutMs?: number;
	directOrigin?: { host: string; port: number } | null;
}

export async function probePolling(args: ProbeArgs): Promise<PollingResult> {
	const { target, libraryDetect, timeoutMs = DEFAULT_TIMEOUT_MS } = args;
	const start = performance.now();

	if (libraryDetect.details.library !== "socket.io") {
		return {
			phase: "polling",
			outcome: "skipped",
			durationMs: 0,
			summary: "Polling probe only runs for Socket.IO targets in v0.1",
			details: {
				probedUrl: "",
				status: null,
				openPacketReceived: false,
				openPacket: null,
			},
		};
	}

	// Build the polling URL using the host/port/path from the target, but force
	// transport=polling and EIO=4. Preserve any other query params the user passed.
	const probeUrl = buildPollingUrl(target);

	const directOrigin = args.directOrigin ?? null;
	const dispatcher = directOrigin
		? new Agent({
				connect: {
					host: directOrigin.host,
					port: directOrigin.port,
					servername: target.host,
					rejectUnauthorized: false,
				},
				headersTimeout: timeoutMs,
				bodyTimeout: timeoutMs,
			})
		: undefined;

	try {
		const res = await request(probeUrl, {
			method: "GET",
			headers: {
				"user-agent": "ws-doctor/0.1.0",
				accept: "*/*",
			},
			dispatcher,
			signal: AbortSignal.timeout(timeoutMs),
		});

		const body = await readBody(res.body, MAX_BODY);
		const durationMs = Math.round(performance.now() - start);

		const openPacket = parseEngineIoOpenPacket(body);

		await dispatcher?.close().catch(() => {});

		if (openPacket) {
			return {
				phase: "polling",
				outcome: "ok",
				durationMs,
				summary: `Polling handshake OK (sid ${openPacket.sid ?? "?"})`,
				details: {
					probedUrl: probeUrl,
					status: res.statusCode,
					openPacketReceived: true,
					openPacket: openPacket as Record<string, unknown>,
				},
			};
		}

		return {
			phase: "polling",
			outcome: "fail",
			durationMs,
			summary: `Polling returned ${res.statusCode} but no Engine.IO open packet`,
			error: "no open packet in body",
			details: {
				probedUrl: probeUrl,
				status: res.statusCode,
				openPacketReceived: false,
				openPacket: null,
			},
		};
	} catch (err: unknown) {
		const durationMs = Math.round(performance.now() - start);
		await dispatcher?.close().catch(() => {});
		const message = err instanceof Error ? err.message : String(err);
		return {
			phase: "polling",
			outcome: "fail",
			durationMs,
			summary: "Polling request failed",
			error: message,
			details: {
				probedUrl: probeUrl,
				status: null,
				openPacketReceived: false,
				openPacket: null,
			},
		};
	}
}

function buildPollingUrl(target: Target): string {
	const url = new URL(target.url.toString());
	// HTTP scheme for the polling probe even if target is ws:/wss:
	if (url.protocol === "ws:") url.protocol = "http:";
	if (url.protocol === "wss:") url.protocol = "https:";

	// Ensure the standard Engine.IO params for polling
	url.searchParams.set("EIO", url.searchParams.get("EIO") ?? "4");
	url.searchParams.set("transport", "polling");
	// Remove sid if present — we want a fresh handshake
	url.searchParams.delete("sid");

	return url.toString();
}

async function readBody(
	body: import("undici").Dispatcher.ResponseData["body"],
	maxBytes: number,
): Promise<string> {
	const chunks: Buffer[] = [];
	let total = 0;
	for await (const chunk of body) {
		const buf = Buffer.isBuffer(chunk) ? chunk : Buffer.from(chunk);
		chunks.push(buf);
		total += buf.length;
		if (total >= maxBytes) break;
	}
	return Buffer.concat(chunks).slice(0, maxBytes).toString("utf8");
}

/**
 * Engine.IO v4 polling open packet has the form `0{...json...}`. Older
 * versions or different framings may use `<length>:0{...}` (EIO v3). Try to
 * extract the JSON payload from either.
 */
function parseEngineIoOpenPacket(body: string): {
	sid?: string;
	upgrades?: string[];
	pingInterval?: number;
	pingTimeout?: number;
	maxPayload?: number;
} | null {
	if (!body) return null;

	// EIO v4 framing: starts with literal "0" then JSON
	let jsonPart: string | null = null;
	if (body.startsWith("0{")) {
		jsonPart = body.slice(1);
	} else {
		// EIO v3 framing: "<len>:0{...}". Look for ":0{".
		const idx = body.indexOf(":0{");
		if (idx >= 0) jsonPart = body.slice(idx + 2);
	}

	if (!jsonPart) return null;

	// Trim to the matching '}' — body may contain additional packets
	const close = findMatchingBrace(jsonPart);
	if (close < 0) return null;
	const jsonText = jsonPart.slice(0, close + 1);

	try {
		const parsed = JSON.parse(jsonText);
		if (parsed && typeof parsed === "object" && "sid" in parsed) {
			return parsed;
		}
		return null;
	} catch {
		return null;
	}
}

function findMatchingBrace(str: string): number {
	if (str[0] !== "{") return -1;
	let depth = 0;
	let inString = false;
	let escape = false;
	for (let i = 0; i < str.length; i++) {
		const c = str[i];
		if (escape) {
			escape = false;
			continue;
		}
		if (c === "\\") {
			escape = true;
			continue;
		}
		if (c === '"') inString = !inString;
		else if (!inString) {
			if (c === "{") depth++;
			else if (c === "}") {
				depth--;
				if (depth === 0) return i;
			}
		}
	}
	return -1;
}
