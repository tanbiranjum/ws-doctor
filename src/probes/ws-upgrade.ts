/**
 * WebSocket upgrade probe — the heart of ws-doctor.
 *
 * Opens a raw TCP/TLS connection to the target, sends a real WS upgrade
 * request, and reports exactly what came back. The fine-grained outcome
 * (101, 4xx, silent-hang, closed-without-response, etc.) is what powers most
 * of the rule engine's diagnoses.
 *
 * We use raw sockets instead of a higher-level WS client because we need to
 * observe the byte-level outcome — including "server accepted the connection
 * then said nothing", which a WS client library hides behind a generic
 * connection-failed error.
 */

import * as net from "node:net";
import * as tls from "node:tls";
import { randomBytes } from "node:crypto";
import type { Target, WsUpgradeResult, WsUpgradeOutcomeKind } from "../types.js";

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_RESPONSE_BYTES = 4096;

interface ProbeArgs {
	target: Target;
	timeoutMs?: number;
	directOrigin?: { host: string; port: number } | null;
	/**
	 * Optional Origin header to send. Omitted entirely by default — a
	 * diagnostic tool has no real origin and sending one (especially the
	 * target host) trips strict CORS allow-lists.
	 */
	origin?: string | null;
}

export async function probeWsUpgrade(args: ProbeArgs): Promise<WsUpgradeResult> {
	const { target, timeoutMs = DEFAULT_TIMEOUT_MS } = args;
	const startAll = performance.now();
	const directOrigin = args.directOrigin ?? null;

	const connectHost = directOrigin?.host ?? target.host;
	const connectPort = directOrigin?.port ?? target.port;
	const sniHost = target.host;

	const probedUrl = `${target.secure ? "wss" : "ws"}://${target.host}:${target.port}${target.pathWithQuery}`;
	const wsKey = randomBytes(16).toString("base64");

	const upgradeRequest = buildUpgradeRequest({
		host: target.host,
		port: target.port,
		secure: target.secure,
		pathWithQuery: target.pathWithQuery,
		wsKey,
		origin: args.origin ?? null,
	});

	return new Promise<WsUpgradeResult>((resolve) => {
		let socket: net.Socket | tls.TLSSocket;
		let received = Buffer.alloc(0);
		let requestSentAt = 0;
		let firstByteAt: number | null = null;
		let resolved = false;

		function finish(
			outcomeKind: WsUpgradeOutcomeKind,
			summary: string,
			error?: string,
		) {
			if (resolved) return;
			resolved = true;
			const durationMs = Math.round(performance.now() - startAll);
			const parsed = parseHttpResponse(received);
			const outcomeFlag: WsUpgradeResult["outcome"] =
				outcomeKind === "switching-protocols" ? "ok" : "fail";

			try {
				socket?.destroy();
			} catch {
				// ignore
			}

			resolve({
				phase: "ws-upgrade",
				outcome: outcomeFlag,
				durationMs,
				summary,
				error,
				details: {
					probedUrl,
					outcomeKind,
					responseStatus: parsed?.status ?? null,
					responseHeaders: parsed?.headers ?? {},
					bytesReceived: received.length,
					bodySnippet: received
						.subarray(0, Math.min(received.length, MAX_RESPONSE_BYTES))
						.toString("utf8"),
					timeToFirstByteMs:
						firstByteAt !== null && requestSentAt
							? Math.round(firstByteAt - requestSentAt)
							: null,
					httpVersionUsed: "1.1",
					originSent: args.origin ?? null,
				},
			});
		}

		const overallTimer = setTimeout(() => {
			if (received.length === 0) {
				finish(
					"silent-hang",
					`No response from server in ${timeoutMs}ms (TCP/TLS connected, request sent, no bytes received)`,
				);
			} else {
				// We got some bytes but no complete response within timeout.
				finish(
					"closed-without-response",
					`Partial response (${received.length} bytes) but no complete HTTP response in ${timeoutMs}ms`,
				);
			}
		}, timeoutMs);

		try {
			if (target.secure) {
				socket = tls.connect({
					host: connectHost,
					port: connectPort,
					servername: sniHost,
					rejectUnauthorized: false,
					ALPNProtocols: ["http/1.1"], // force HTTP/1.1 — WS upgrade needs it
				});
				socket.once("secureConnect", onConnected);
			} else {
				socket = net.connect({ host: connectHost, port: connectPort });
				socket.once("connect", onConnected);
			}
		} catch (err) {
			clearTimeout(overallTimer);
			finish(
				"connect-refused",
				"Could not initiate connection",
				err instanceof Error ? err.message : String(err),
			);
			return;
		}

		function onConnected() {
			socket.write(upgradeRequest, () => {
				requestSentAt = performance.now();
			});

			socket.on("data", (chunk: Buffer) => {
				if (firstByteAt === null) firstByteAt = performance.now();
				received = Buffer.concat([received, chunk]);

				// Try to parse as full HTTP response. If we have headers complete,
				// finish with the appropriate outcome.
				const parsed = parseHttpResponse(received);
				if (parsed) {
					clearTimeout(overallTimer);
					if (parsed.status === 101) {
						finish("switching-protocols", "WS upgrade succeeded (101)");
					} else if (parsed.status >= 300 && parsed.status < 400) {
						finish(
							"redirected",
							`Server returned ${parsed.status} redirect (WS clients don't follow redirects)`,
						);
					} else {
						finish(
							"rejected",
							`Server rejected upgrade with HTTP ${parsed.status}`,
						);
					}
				}

				// Hard cap to avoid unbounded receive
				if (received.length >= MAX_RESPONSE_BYTES) {
					clearTimeout(overallTimer);
					finish(
						"closed-without-response",
						`Received ${received.length} bytes but no recognizable HTTP response`,
					);
				}
			});

			socket.on("end", () => {
				if (resolved) return;
				clearTimeout(overallTimer);
				if (received.length === 0) {
					finish(
						"closed-without-response",
						"Server accepted connection then closed without sending any data",
					);
				} else {
					const parsed = parseHttpResponse(received);
					if (parsed?.status === 101) {
						finish("switching-protocols", "WS upgrade succeeded (101)");
					} else {
						finish(
							"closed-without-response",
							`Connection closed with ${received.length} bytes received (incomplete response)`,
						);
					}
				}
			});
		}

		socket!.on("error", (err: Error) => {
			if (resolved) return;
			clearTimeout(overallTimer);
			const code = (err as NodeJS.ErrnoException).code ?? "";
			if (code === "ECONNREFUSED" || code === "ENETUNREACH") {
				finish("connect-refused", "TCP connection refused", err.message);
			} else if (code.startsWith("ERR_TLS") || err.message.includes("certificate")) {
				finish("tls-error", `TLS error: ${err.message}`, err.message);
			} else {
				finish("connect-refused", `Connection error: ${err.message}`, err.message);
			}
		});
	});
}

function buildUpgradeRequest(args: {
	host: string;
	port: number;
	secure: boolean;
	pathWithQuery: string;
	wsKey: string;
	origin: string | null;
}): string {
	const isDefaultPort = (args.secure && args.port === 443) || (!args.secure && args.port === 80);
	const hostHeader = isDefaultPort ? args.host : `${args.host}:${args.port}`;
	const originLine = args.origin ? `Origin: ${args.origin}\r\n` : "";
	return (
		`GET ${args.pathWithQuery} HTTP/1.1\r\n` +
		`Host: ${hostHeader}\r\n` +
		`User-Agent: ws-doctor/0.1.3\r\n` +
		`Upgrade: websocket\r\n` +
		`Connection: Upgrade\r\n` +
		`Sec-WebSocket-Version: 13\r\n` +
		`Sec-WebSocket-Key: ${args.wsKey}\r\n` +
		originLine +
		`\r\n`
	);
}

/**
 * Parse a (possibly partial) HTTP response from a Buffer. Returns null if the
 * headers are not yet complete.
 */
function parseHttpResponse(buf: Buffer): {
	status: number;
	headers: Record<string, string>;
} | null {
	const text = buf.toString("utf8");
	const headerEnd = text.indexOf("\r\n\r\n");
	if (headerEnd < 0) return null;

	const headerSection = text.slice(0, headerEnd);
	const lines = headerSection.split("\r\n");
	const statusLine = lines[0];
	if (!statusLine) return null;
	const match = /^HTTP\/[\d.]+\s+(\d{3})/.exec(statusLine);
	if (!match) return null;
	const status = Number(match[1]);

	const headers: Record<string, string> = {};
	for (let i = 1; i < lines.length; i++) {
		const line = lines[i];
		const colon = line.indexOf(":");
		if (colon < 0) continue;
		const k = line.slice(0, colon).trim().toLowerCase();
		const v = line.slice(colon + 1).trim();
		// Combine duplicate headers (rare but possible)
		headers[k] = headers[k] ? `${headers[k]}, ${v}` : v;
	}

	return { status, headers };
}
