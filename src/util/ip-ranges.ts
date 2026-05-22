/**
 * Minimal CIDR-based provider detection for IPv4. Used to attribute resolved
 * IPs to common CDNs / proxies so the rule engine can apply provider-specific
 * diagnoses (e.g., "polling works but WS hangs AND target is Cloudflare-proxied
 * = likely CF WebSocket toggle off").
 *
 * Not exhaustive — only the most common public CDN ranges. PRs welcome.
 */

import type { DetectedProvider } from "../types.js";

interface Range {
	cidr: string;
	provider: DetectedProvider;
}

// Hand-picked common ranges. Source: each provider's public IP-range docs.
// We only need enough to detect the provider, not every prefix they own.
const KNOWN_RANGES: Range[] = [
	// Cloudflare — official list at https://www.cloudflare.com/ips-v4
	{ cidr: "104.16.0.0/13", provider: "cloudflare" },
	{ cidr: "104.24.0.0/14", provider: "cloudflare" },
	{ cidr: "172.64.0.0/13", provider: "cloudflare" },
	{ cidr: "162.158.0.0/15", provider: "cloudflare" },
	{ cidr: "141.101.64.0/18", provider: "cloudflare" },
	{ cidr: "108.162.192.0/18", provider: "cloudflare" },
	{ cidr: "190.93.240.0/20", provider: "cloudflare" },
	{ cidr: "188.114.96.0/20", provider: "cloudflare" },
	{ cidr: "197.234.240.0/22", provider: "cloudflare" },
	{ cidr: "198.41.128.0/17", provider: "cloudflare" },
	{ cidr: "131.0.72.0/22", provider: "cloudflare" },
	{ cidr: "173.245.48.0/20", provider: "cloudflare" },
	{ cidr: "103.21.244.0/22", provider: "cloudflare" },
	{ cidr: "103.22.200.0/22", provider: "cloudflare" },
	{ cidr: "103.31.4.0/22", provider: "cloudflare" },
	// AWS CloudFront — a sample of the most common ranges
	{ cidr: "13.32.0.0/15", provider: "aws-cloudfront" },
	{ cidr: "13.224.0.0/14", provider: "aws-cloudfront" },
	{ cidr: "52.84.0.0/15", provider: "aws-cloudfront" },
	{ cidr: "54.192.0.0/16", provider: "aws-cloudfront" },
	{ cidr: "54.230.0.0/16", provider: "aws-cloudfront" },
	{ cidr: "99.84.0.0/16", provider: "aws-cloudfront" },
	{ cidr: "99.86.0.0/16", provider: "aws-cloudfront" },
	{ cidr: "108.138.0.0/15", provider: "aws-cloudfront" },
	{ cidr: "108.156.0.0/14", provider: "aws-cloudfront" },
	{ cidr: "143.204.0.0/16", provider: "aws-cloudfront" },
	{ cidr: "205.251.192.0/19", provider: "aws-cloudfront" },
	// Fastly
	{ cidr: "151.101.0.0/16", provider: "fastly" },
	{ cidr: "146.75.0.0/17", provider: "fastly" },
	{ cidr: "199.232.0.0/16", provider: "fastly" },
	{ cidr: "23.235.32.0/20", provider: "fastly" },
	{ cidr: "43.249.72.0/22", provider: "fastly" },
	// Google Cloud / Google Front End
	{ cidr: "35.190.0.0/15", provider: "google-cloud" },
	{ cidr: "130.211.0.0/22", provider: "google-cloud" },
	{ cidr: "34.96.0.0/14", provider: "google-cloud" },
	// Vercel
	{ cidr: "76.76.21.0/24", provider: "vercel" },
	{ cidr: "76.76.22.0/23", provider: "vercel" },
];

function ipv4ToInt(ip: string): number | null {
	const parts = ip.split(".");
	if (parts.length !== 4) return null;
	let n = 0;
	for (const part of parts) {
		const num = Number(part);
		if (!Number.isInteger(num) || num < 0 || num > 255) return null;
		n = (n << 8) | num;
	}
	// `>>> 0` to coerce back to unsigned 32-bit
	return n >>> 0;
}

function ipInCidr(ip: string, cidr: string): boolean {
	const [network, bitsStr] = cidr.split("/");
	if (!network || !bitsStr) return false;
	const bits = Number(bitsStr);
	if (!Number.isInteger(bits) || bits < 0 || bits > 32) return false;
	const ipInt = ipv4ToInt(ip);
	const netInt = ipv4ToInt(network);
	if (ipInt === null || netInt === null) return false;
	if (bits === 0) return true;
	const mask = (~0 << (32 - bits)) >>> 0;
	return (ipInt & mask) === (netInt & mask);
}

/**
 * Identify the provider for an IPv4 address against known ranges.
 * Returns "unknown" if no range matches.
 */
export function detectProviderForIp(ip: string): DetectedProvider {
	for (const range of KNOWN_RANGES) {
		if (ipInCidr(ip, range.cidr)) return range.provider;
	}
	return "unknown";
}

/**
 * Identify the most-likely provider across a list of addresses. Picks the
 * first non-unknown match.
 */
export function detectProviderForAddresses(
	addresses: string[],
): DetectedProvider {
	for (const ip of addresses) {
		const p = detectProviderForIp(ip);
		if (p !== "unknown") return p;
	}
	return "unknown";
}
