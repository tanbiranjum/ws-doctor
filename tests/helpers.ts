/**
 * Test helpers — builders for canned Trace objects we use to exercise rules
 * without making network calls.
 */

import type {
	DetectedProvider,
	DnsResult,
	HttpResult,
	LibraryDetectResult,
	PollingResult,
	Target,
	TlsResult,
	Trace,
	WsUpgradeOutcomeKind,
	WsUpgradeResult,
} from "../src/types.js";

export function makeTarget(overrides: Partial<Target> = {}): Target {
	const rawUrl =
		overrides.rawUrl ??
		"wss://example.com/socket.io/?EIO=4&transport=websocket";
	const url = new URL(rawUrl);
	return {
		rawUrl,
		url,
		host: url.hostname,
		port: Number(url.port || 443),
		secure: url.protocol === "wss:",
		pathWithQuery: url.pathname + url.search,
		path: url.pathname,
		...overrides,
	};
}

export function makeDns(
	provider: DetectedProvider,
	addresses: string[] = ["1.2.3.4"],
): DnsResult {
	return {
		phase: "dns",
		outcome: "ok",
		durationMs: 5,
		summary: `dns ok provider=${provider}`,
		details: { host: "example.com", addresses, provider },
	};
}

export function makeTls(opts: Partial<TlsResult["details"]> = {}): TlsResult {
	return {
		phase: "tls",
		outcome: "ok",
		durationMs: 50,
		summary: "tls ok",
		details: {
			host: "example.com",
			port: 443,
			tlsVersion: "TLSv1.3",
			alpnProtocol: "h2",
			cert: {
				subject: "CN=example.com",
				issuer: "CN=Let's Encrypt",
				subjectAltNames: ["example.com", "*.example.com"],
				validFrom: "2026-01-01",
				validTo: "2026-04-01",
				matchesHost: true,
			},
			...opts,
		},
	};
}

export function makeHttp(opts: Partial<HttpResult["details"]> = {}): HttpResult {
	return {
		phase: "http",
		outcome: "ok",
		durationMs: 80,
		summary: "http 200",
		details: {
			httpVersion: "1.1",
			status: 200,
			headers: {},
			bodySnippet: "",
			bodyContentType: null,
			bodyLooksLike: "empty",
			...opts,
		},
	};
}

export function makeLibrary(
	library: LibraryDetectResult["details"]["library"] = "socket.io",
): LibraryDetectResult {
	return {
		phase: "library-detect",
		outcome: "ok",
		durationMs: 1,
		summary: `library=${library}`,
		details: { library, evidence: {} },
	};
}

export function makePolling(
	openPacketReceived: boolean,
	status = openPacketReceived ? 200 : 404,
): PollingResult {
	return {
		phase: "polling",
		outcome: openPacketReceived ? "ok" : "fail",
		durationMs: 50,
		summary: `polling ${openPacketReceived ? "ok" : "fail"}`,
		details: {
			probedUrl: "https://example.com/socket.io/?EIO=4&transport=polling",
			status,
			openPacketReceived,
			openPacket: openPacketReceived
				? { sid: "abc", upgrades: ["websocket"], pingInterval: 25000 }
				: null,
		},
	};
}

export function makeWs(
	outcomeKind: WsUpgradeOutcomeKind,
	overrides: Partial<WsUpgradeResult["details"]> = {},
): WsUpgradeResult {
	const status =
		outcomeKind === "switching-protocols"
			? 101
			: outcomeKind === "rejected"
				? 403
				: outcomeKind === "redirected"
					? 301
					: null;
	return {
		phase: "ws-upgrade",
		outcome: outcomeKind === "switching-protocols" ? "ok" : "fail",
		durationMs: 200,
		summary: `ws ${outcomeKind}`,
		details: {
			probedUrl: "wss://example.com/socket.io/",
			outcomeKind,
			responseStatus: status,
			responseHeaders: {},
			bytesReceived: 0,
			bodySnippet: "",
			timeToFirstByteMs: status ? 100 : null,
			httpVersionUsed: "1.1",
			...overrides,
		},
	};
}

export function makeTrace(parts: Partial<Trace["probes"]> = {}): Trace {
	return {
		target: makeTarget(),
		startedAt: new Date().toISOString(),
		totalDurationMs: 500,
		probes: parts,
		directOrigin: null,
	};
}
