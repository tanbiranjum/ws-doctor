/**
 * DNS probe — resolves the target host's A records and identifies the
 * provider (CDN/cloud) from the resulting IPs.
 *
 * Why this matters: knowing the target is behind Cloudflare (vs. a direct
 * origin) changes which diagnoses make sense later. The rule engine uses
 * `details.provider` extensively.
 */

import { promises as dns } from "node:dns";
import { detectProviderForAddresses } from "../util/ip-ranges.js";
import type { DnsResult, Target } from "../types.js";

export async function probeDns(target: Target): Promise<DnsResult> {
	const start = performance.now();
	const host = target.host;

	try {
		// resolve4 returns IPv4 only; we also try IPv6 but don't fail if missing.
		const v4 = await dns.resolve4(host).catch(() => [] as string[]);
		const v6 = await dns.resolve6(host).catch(() => [] as string[]);
		const addresses = [...v4, ...v6];

		const durationMs = Math.round(performance.now() - start);

		if (addresses.length === 0) {
			return {
				phase: "dns",
				outcome: "fail",
				durationMs,
				summary: `No A/AAAA records for ${host}`,
				error: "NXDOMAIN or no addresses returned",
				details: { host, addresses: [], provider: "unknown" },
			};
		}

		const provider = detectProviderForAddresses(addresses);

		let summary = `Resolved ${addresses.length} address(es)`;
		if (provider !== "unknown") summary += ` — detected ${provider}`;

		return {
			phase: "dns",
			outcome: "ok",
			durationMs,
			summary,
			details: { host, addresses, provider },
		};
	} catch (err: unknown) {
		const durationMs = Math.round(performance.now() - start);
		const message = err instanceof Error ? err.message : String(err);
		return {
			phase: "dns",
			outcome: "fail",
			durationMs,
			summary: `DNS lookup failed for ${host}`,
			error: message,
			details: { host, addresses: [], provider: "unknown" },
		};
	}
}
