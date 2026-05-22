/**
 * HTTP probe — fetches the target URL via undici and reports status, headers,
 * and a body snippet. Used as a sanity check that the host responds to plain
 * HTTP at all, and to feed rules that look for telltale signs:
 *  - `server: cloudflare` + `cf-ray` headers confirm CF is proxying
 *  - `content-disposition: ... index.html` and HTML body = SPA fallback host
 *    (we're hitting the frontend, not the backend)
 *  - `cf-mitigated: challenge` = CF security challenge
 */

import { Agent, request } from "undici";
import type { HttpResult, Target } from "../types.js";

const DEFAULT_TIMEOUT_MS = 10_000;
const MAX_BODY_SNIPPET = 1024;

interface ProbeArgs {
	target: Target;
	timeoutMs?: number;
	/** Bypass DNS: connect directly to this origin */
	directOrigin?: { host: string; port: number } | null;
}

export async function probeHttp(args: ProbeArgs): Promise<HttpResult> {
	const { target, timeoutMs = DEFAULT_TIMEOUT_MS } = args;
	const start = performance.now();
	const directOrigin = args.directOrigin ?? null;

	const dispatcher = directOrigin
		? new Agent({
				connect: {
					host: directOrigin.host,
					port: directOrigin.port,
					// Preserve SNI to the original target host name
					servername: target.host,
					rejectUnauthorized: false,
				},
				headersTimeout: timeoutMs,
				bodyTimeout: timeoutMs,
			})
		: undefined;

	// Build the HTTP URL we probe (root path on the target). Undici doesn't
	// speak ws:/wss: — coerce to http:/https: for the reachability check.
	const httpScheme =
		target.url.protocol === "wss:" || target.url.protocol === "https:"
			? "https:"
			: "http:";
	const probeUrl = `${httpScheme}//${target.host}${target.port && !isDefaultPort(httpScheme, target.port) ? `:${target.port}` : ""}/`;

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

		const headers = normalizeHeaders(res.headers);
		const contentType = headers["content-type"] ?? null;
		const body = await readBodySnippet(res.body, MAX_BODY_SNIPPET);
		const bodyLooksLike = classifyBody(contentType, body);

		const durationMs = Math.round(performance.now() - start);

		await dispatcher?.close().catch(() => {});

		return {
			phase: "http",
			outcome: "ok",
			durationMs,
			summary: `HTTP ${res.statusCode} ${headers["server"] ?? ""}`.trim(),
			details: {
				httpVersion: "unknown", // undici doesn't expose version cleanly per-request
				status: res.statusCode,
				headers,
				bodySnippet: body,
				bodyContentType: contentType,
				bodyLooksLike,
			},
		};
	} catch (err: unknown) {
		const durationMs = Math.round(performance.now() - start);
		await dispatcher?.close().catch(() => {});
		const message = err instanceof Error ? err.message : String(err);
		return {
			phase: "http",
			outcome: "fail",
			durationMs,
			summary: `HTTP request failed`,
			error: message,
			details: {
				httpVersion: "unknown",
				status: null,
				headers: {},
				bodySnippet: "",
				bodyContentType: null,
				bodyLooksLike: "empty",
			},
		};
	}
}

function isDefaultPort(protocol: string, port: number): boolean {
	if (protocol === "https:" || protocol === "wss:") return port === 443;
	if (protocol === "http:" || protocol === "ws:") return port === 80;
	return false;
}

function normalizeHeaders(
	raw: Record<string, string | string[] | undefined>,
): Record<string, string> {
	const out: Record<string, string> = {};
	for (const [key, val] of Object.entries(raw)) {
		if (val === undefined) continue;
		const lower = key.toLowerCase();
		out[lower] = Array.isArray(val) ? val.join(", ") : val;
	}
	return out;
}

async function readBodySnippet(
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

function classifyBody(
	contentType: string | null,
	body: string,
): HttpResult["details"]["bodyLooksLike"] {
	if (!body) return "empty";
	if (contentType) {
		if (contentType.includes("html")) return "html";
		if (contentType.includes("json")) return "json";
		if (contentType.startsWith("text/")) return "text";
		if (contentType.startsWith("application/octet-stream")) return "binary";
	}
	// Fallback: look at content
	const trimmed = body.trim();
	if (trimmed.startsWith("<")) return "html";
	if (trimmed.startsWith("{") || trimmed.startsWith("[")) return "json";
	return "text";
}
