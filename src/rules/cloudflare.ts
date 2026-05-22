/**
 * Cloudflare-specific rules.
 *
 * Rules in this file fire only when DNS detected Cloudflare in the resolution
 * chain. They describe failure modes that are specific to (or most commonly
 * caused by) Cloudflare configuration.
 */

import type { Rule } from "../types.js";

const cfWsToggleLikelyOff: Rule = {
	id: "cf.ws-toggle-likely-off",
	title: "Cloudflare WebSockets toggle likely disabled",
	confidence: 0.55,
	match: (trace) => {
		const dns = trace.probes.dns;
		const polling = trace.probes.polling;
		const ws = trace.probes.wsUpgrade;
		return (
			dns?.details.provider === "cloudflare" &&
			polling?.details.openPacketReceived === true &&
			ws?.details.outcomeKind === "silent-hang"
		);
	},
	cause:
		"Polling works but the WebSocket upgrade returns no response from a Cloudflare-proxied host. This is the textbook symptom of Cloudflare not forwarding the upgrade — usually because the per-zone WebSockets toggle is off.",
	remediation: [
		"Cloudflare dashboard → select the zone → Network → WebSockets → On.",
		"Also confirm Security → Bots → Bot Fight Mode is Off (or excludes /socket.io/* / your WS path).",
		"Confirm Security → Settings → Security Level is not 'I'm Under Attack'.",
		"Isolation: temporarily set the DNS record to 'DNS only' (grey cloud) and rerun. If the upgrade succeeds, Cloudflare is definitively the cause.",
	],
	references: [
		"https://developers.cloudflare.com/network/websockets/",
	],
};

const cfChallengeBlockingUpgrade: Rule = {
	id: "cf.challenge-blocking-upgrade",
	title: "Cloudflare security challenge blocking WS upgrade",
	confidence: 0.7,
	match: (trace) => {
		const dns = trace.probes.dns;
		const ws = trace.probes.wsUpgrade;
		if (dns?.details.provider !== "cloudflare") return false;
		if (!ws) return false;
		// CF "Managed Challenge" / challenge interstitials commonly return 200/403
		// with HTML or specific cf-mitigated headers.
		const mitigated = ws.details.responseHeaders["cf-mitigated"];
		if (mitigated) return true;
		// 403 with cloudflare server header
		if (
			ws.details.responseStatus === 403 &&
			(ws.details.responseHeaders["server"] ?? "").toLowerCase().includes("cloudflare")
		) {
			return true;
		}
		// 200 with HTML body from Cloudflare on a WS upgrade attempt is suspicious
		if (
			ws.details.responseStatus === 200 &&
			(ws.details.responseHeaders["content-type"] ?? "").includes("html") &&
			(ws.details.responseHeaders["server"] ?? "").toLowerCase().includes("cloudflare")
		) {
			return true;
		}
		return false;
	},
	cause:
		"Cloudflare is intercepting the WebSocket upgrade and returning a security/challenge page instead of forwarding it to origin.",
	remediation: [
		"Dashboard → Security → Bots → set Bot Fight Mode to Off (or exclude your WS path).",
		"Dashboard → Security → Settings → set Security Level to Medium or lower (NOT 'I'm Under Attack').",
		"Dashboard → Security → WAF → check Custom Rules and Managed Rules for anything matching /socket.io/ or the Upgrade header.",
	],
	references: [
		"https://developers.cloudflare.com/waf/",
	],
};

export const cloudflareRules: Rule[] = [
	cfWsToggleLikelyOff,
	cfChallengeBlockingUpgrade,
];
