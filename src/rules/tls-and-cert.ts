/**
 * TLS and certificate rules — failure modes at the transport layer that
 * masquerade as WS-level issues.
 */

import type { Rule } from "../types.js";

const certHostMismatch: Rule = {
	id: "tls.cert-host-mismatch",
	title: "TLS cert does not include the target hostname",
	confidence: 0.7,
	match: (trace) => {
		const tls = trace.probes.tls;
		if (!tls || tls.outcome !== "ok") return false;
		const cert = tls.details.cert;
		if (!cert) return false;
		return cert.matchesHost === false;
	},
	cause:
		"The server's TLS certificate does not include the hostname you're connecting to in its CN or Subject Alternative Names. Strict WS clients will refuse this connection.",
	remediation: [
		"Confirm you're connecting to the right hostname (typos like extra/missing subdomain).",
		"If using a CDN edge cert, confirm the cert's SAN list covers your subdomain.",
		"If hitting an origin directly (e.g. via --direct), the origin may only have a cert valid for the public hostname when fronted by the CDN.",
	],
};

const tlsHandshakeFailed: Rule = {
	id: "tls.handshake-failed",
	title: "TLS handshake failed",
	confidence: 0.9,
	match: (trace) => {
		const tls = trace.probes.tls;
		return tls?.outcome === "fail";
	},
	cause:
		"Could not establish a TLS session with the target. No higher-layer WS issue can be diagnosed until this succeeds.",
	remediation: [
		"Check the target host and port are correct.",
		"If the server uses a self-signed or otherwise unusual cert chain, that may be the cause — confirm via `openssl s_client -connect host:port -servername host`.",
		"Confirm your client's clock is not significantly skewed.",
	],
};

export const tlsRules: Rule[] = [certHostMismatch, tlsHandshakeFailed];
