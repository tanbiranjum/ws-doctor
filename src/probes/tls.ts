/**
 * TLS probe — completes a TLS handshake against the target and reports
 * negotiated version, ALPN, and certificate details.
 *
 * Why this matters: cert mismatches and ALPN-side surprises (e.g. server
 * forcing HTTP/2 for WebSocket attempts) are real failure modes. Capturing
 * the cert's SAN list also helps the rule engine detect "I'm hitting the
 * wrong virtual host" (cert SAN doesn't include target host).
 */

import * as tls from "node:tls";
import type { TlsResult, Target } from "../types.js";

const DEFAULT_TIMEOUT_MS = 10_000;

interface ConnectArgs {
	host: string;
	port: number;
	servername: string;
}

export async function probeTls(
	target: Target,
	connectArgs?: Partial<ConnectArgs>,
	timeoutMs = DEFAULT_TIMEOUT_MS,
): Promise<TlsResult> {
	const start = performance.now();

	if (!target.secure) {
		return {
			phase: "tls",
			outcome: "skipped",
			durationMs: 0,
			summary: "Target is not TLS (ws://, http://). Skipping TLS probe.",
			details: {
				host: target.host,
				port: target.port,
				tlsVersion: null,
				alpnProtocol: null,
				cert: null,
			},
		};
	}

	const host = connectArgs?.host ?? target.host;
	const port = connectArgs?.port ?? target.port;
	// Always SNI the requested target host so we exercise the same vhost the
	// real WS client would, even when --direct overrides the connect address.
	const servername = connectArgs?.servername ?? target.host;

	return new Promise<TlsResult>((resolve) => {
		const socket = tls.connect({
			host,
			port,
			servername,
			ALPNProtocols: ["h2", "http/1.1"],
			rejectUnauthorized: false, // we report cert validity ourselves
		});

		const timer = setTimeout(() => {
			socket.destroy();
			const durationMs = Math.round(performance.now() - start);
			resolve({
				phase: "tls",
				outcome: "fail",
				durationMs,
				summary: `TLS handshake timed out after ${timeoutMs}ms`,
				error: "timeout",
				details: {
					host,
					port,
					tlsVersion: null,
					alpnProtocol: null,
					cert: null,
				},
			});
		}, timeoutMs);

		socket.once("secureConnect", () => {
			clearTimeout(timer);
			const durationMs = Math.round(performance.now() - start);

			const cert = socket.getPeerCertificate(false);
			const sanRaw = cert.subjectaltname as string | string[] | undefined;
			const sanStr = Array.isArray(sanRaw) ? sanRaw.join(", ") : sanRaw;
			const sans = parseSans(sanStr);
			const cnRaw = cert.subject?.CN as string | string[] | undefined;
			const cn = Array.isArray(cnRaw) ? cnRaw[0] : cnRaw;
			const matchesHost = hostMatchesCert(servername, cn, sans);

			socket.destroy();

			resolve({
				phase: "tls",
				outcome: "ok",
				durationMs,
				summary: `TLS ${socket.getProtocol() ?? "?"} via ALPN=${socket.alpnProtocol ?? "(none)"}`,
				details: {
					host,
					port,
					tlsVersion: socket.getProtocol(),
					alpnProtocol: socket.alpnProtocol || null,
					cert: cert && Object.keys(cert).length
						? {
								subject: formatDn(cert.subject),
								issuer: formatDn(cert.issuer),
								subjectAltNames: sans,
								validFrom: cert.valid_from ?? null,
								validTo: cert.valid_to ?? null,
								matchesHost,
							}
						: null,
				},
			});
		});

		socket.once("error", (err: Error) => {
			clearTimeout(timer);
			const durationMs = Math.round(performance.now() - start);
			resolve({
				phase: "tls",
				outcome: "fail",
				durationMs,
				summary: `TLS handshake failed`,
				error: err.message,
				details: {
					host,
					port,
					tlsVersion: null,
					alpnProtocol: null,
					cert: null,
				},
			});
		});
	});
}

/**
 * Parse the `subjectaltname` string into an array of DNS names.
 * Example input: 'DNS:example.com, DNS:*.example.com, IP Address:1.2.3.4'
 */
function parseSans(sanStr: string | undefined): string[] {
	if (!sanStr) return [];
	return sanStr
		.split(",")
		.map((s) => s.trim())
		.filter((s) => s.startsWith("DNS:"))
		.map((s) => s.slice(4));
}

function hostMatchesCert(
	host: string,
	cn: string | undefined,
	sans: string[],
): boolean {
	const candidates = [cn, ...sans].filter(Boolean) as string[];
	for (const c of candidates) {
		if (matchHostPattern(host, c)) return true;
	}
	return false;
}

function matchHostPattern(host: string, pattern: string): boolean {
	if (host === pattern) return true;
	if (pattern.startsWith("*.")) {
		const suffix = pattern.slice(1); // ".example.com"
		// Wildcard only matches a single label, not multiple.
		const hostSuffix = host.slice(host.indexOf("."));
		return hostSuffix === suffix && host.split(".").length === pattern.split(".").length;
	}
	return false;
}

function formatDn(dn: tls.PeerCertificate["subject"] | undefined): string | null {
	if (!dn || typeof dn !== "object") return null;
	const parts: string[] = [];
	for (const [k, v] of Object.entries(dn)) {
		if (typeof v === "string") parts.push(`${k}=${v}`);
	}
	return parts.join(", ") || null;
}
