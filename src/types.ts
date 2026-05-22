/**
 * Core shared types for ws-doctor.
 *
 * The flow:
 *   1. The runner executes probes in order, accumulating ProbeResults into a Trace.
 *   2. The Trace is passed to the rule engine, which runs all Rule.match() functions.
 *   3. Matched rules become Diagnosis entries, sorted by confidence.
 *   4. The output formatter renders Trace + Diagnosis to the user.
 *
 * Probes are pure data-gathering — they make network calls and report what
 * happened. Rules are pure pattern-matching — they read the trace and decide
 * what it means. The separation keeps each side easy to extend.
 */

/* ----------------------------------------------------------------------------
 * Targets
 * --------------------------------------------------------------------------*/

export interface Target {
	/** Original URL the user passed, e.g. wss://api.example.com/socket.io/?EIO=4 */
	rawUrl: string;
	/** Parsed URL */
	url: URL;
	/** Host that DNS should resolve (URL.hostname) */
	host: string;
	/** Port (URL.port or default for protocol) */
	port: number;
	/** True if scheme is wss: or https: */
	secure: boolean;
	/** Path + query the WS endpoint expects, e.g. /socket.io/?EIO=4&transport=websocket */
	pathWithQuery: string;
	/** Path only, e.g. /socket.io/ */
	path: string;
}

/* ----------------------------------------------------------------------------
 * Probe results — one per layer
 * --------------------------------------------------------------------------*/

export type Outcome = "ok" | "fail" | "skipped";

export interface ProbeBase {
	phase: string;
	outcome: Outcome;
	/** ms elapsed for this probe */
	durationMs: number;
	/** Short human-readable summary line for output */
	summary: string;
	/** Structured details specific to the probe type */
	details?: unknown;
	/** Error message if outcome === 'fail' (and the failure was an exception) */
	error?: string;
}

/** Known CDN / proxy provider, inferred from resolved IPs. */
export type DetectedProvider =
	| "cloudflare"
	| "aws-cloudfront"
	| "fastly"
	| "akamai"
	| "google-cloud"
	| "vercel"
	| "unknown";

export interface DnsResult extends ProbeBase {
	phase: "dns";
	details: {
		host: string;
		addresses: string[];
		/** First detected provider from address ranges */
		provider: DetectedProvider;
	};
}

export interface TlsResult extends ProbeBase {
	phase: "tls";
	details: {
		host: string;
		port: number;
		tlsVersion: string | null;
		alpnProtocol: string | null;
		cert: {
			subject: string | null;
			issuer: string | null;
			subjectAltNames: string[];
			validFrom: string | null;
			validTo: string | null;
			matchesHost: boolean;
		} | null;
	};
}

export interface HttpResult extends ProbeBase {
	phase: "http";
	details: {
		httpVersion: "1.1" | "2" | "unknown";
		status: number | null;
		/** Lowercased header name -> value (first value if duplicates) */
		headers: Record<string, string>;
		/** First N bytes of body, decoded as utf8 (may be truncated) */
		bodySnippet: string;
		bodyContentType: string | null;
		bodyLooksLike: "html" | "json" | "text" | "binary" | "empty";
	};
}

export type DetectedLibrary = "socket.io" | "raw-ws" | "unknown";

export interface LibraryDetectResult extends ProbeBase {
	phase: "library-detect";
	details: {
		library: DetectedLibrary;
		/** Library-specific metadata, e.g. EIO version, sid availability */
		evidence: Record<string, unknown>;
	};
}

export interface PollingResult extends ProbeBase {
	phase: "polling";
	details: {
		probedUrl: string;
		status: number | null;
		/** Did we get the library-specific open packet? */
		openPacketReceived: boolean;
		/** For Socket.IO: parsed open packet (sid, upgrades, etc.) */
		openPacket: Record<string, unknown> | null;
	};
}

export type WsUpgradeOutcomeKind =
	| "switching-protocols" // 101 — works
	| "rejected" // 4xx/5xx with response headers
	| "silent-hang" // TCP/TLS established, request sent, no response in timeout
	| "connect-refused" // TCP could not establish
	| "tls-error" // TLS handshake failed
	| "closed-without-response" // server accepted then closed without writing anything
	| "redirected"; // 3xx (WS clients don't follow redirects)

export interface WsUpgradeResult extends ProbeBase {
	phase: "ws-upgrade";
	details: {
		probedUrl: string;
		outcomeKind: WsUpgradeOutcomeKind;
		responseStatus: number | null;
		responseHeaders: Record<string, string>;
		bytesReceived: number;
		bodySnippet: string;
		/** Time from request-fully-sent to first byte received (or null if none received) */
		timeToFirstByteMs: number | null;
		/** Was this attempted over HTTP/1.1? (we only do 1.1 in v0.1) */
		httpVersionUsed: "1.1";
	};
}

export type ProbeResult =
	| DnsResult
	| TlsResult
	| HttpResult
	| LibraryDetectResult
	| PollingResult
	| WsUpgradeResult;

/* ----------------------------------------------------------------------------
 * Trace — the full set of probe results from one run
 * --------------------------------------------------------------------------*/

export interface Trace {
	target: Target;
	startedAt: string;
	totalDurationMs: number;
	probes: {
		dns?: DnsResult;
		tls?: TlsResult;
		http?: HttpResult;
		libraryDetect?: LibraryDetectResult;
		polling?: PollingResult;
		wsUpgrade?: WsUpgradeResult;
	};
	/** Were we instructed to bypass DNS and connect to a specific origin? */
	directOrigin: { host: string; port: number } | null;
}

/* ----------------------------------------------------------------------------
 * Rules and diagnoses
 * --------------------------------------------------------------------------*/

export interface Rule {
	/** Stable id, used for telemetry / output cross-references */
	id: string;
	/** Short human description of what this rule identifies */
	title: string;
	/** Confidence 0..1 — pre-defined per rule; engine doesn't re-rank */
	confidence: number;
	/**
	 * Pure function: does this trace fit the rule's fingerprint?
	 * Returns true if matched. Should never throw.
	 */
	match: (trace: Trace) => boolean;
	/** Primary explanation shown to the user when matched */
	cause: string;
	/** Concrete next-step instructions */
	remediation: string[];
	/** Optional links to docs, GitHub issues, etc. */
	references?: string[];
}

export interface Diagnosis {
	rule: Rule;
	matched: true;
}

/* ----------------------------------------------------------------------------
 * Output / CLI plumbing
 * --------------------------------------------------------------------------*/

export interface RunnerOptions {
	target: Target;
	timeoutMs: number;
	directOrigin: { host: string; port: number } | null;
	verbose: boolean;
}

export interface RunResult {
	trace: Trace;
	diagnoses: Diagnosis[];
}
