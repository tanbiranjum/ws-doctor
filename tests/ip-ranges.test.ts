import { describe, expect, it } from "vitest";
import {
	detectProviderForAddresses,
	detectProviderForIp,
} from "../src/util/ip-ranges.js";

describe("detectProviderForIp", () => {
	it("identifies Cloudflare IPs", () => {
		// 104.16.0.0/13 covers 104.16.0.0 — 104.23.255.255
		expect(detectProviderForIp("104.16.132.1")).toBe("cloudflare");
		expect(detectProviderForIp("172.67.166.63")).toBe("cloudflare");
		expect(detectProviderForIp("162.158.50.1")).toBe("cloudflare");
	});

	it("identifies AWS CloudFront IPs", () => {
		expect(detectProviderForIp("13.32.10.1")).toBe("aws-cloudfront");
		expect(detectProviderForIp("99.84.5.5")).toBe("aws-cloudfront");
	});

	it("identifies Fastly IPs", () => {
		expect(detectProviderForIp("151.101.1.1")).toBe("fastly");
		expect(detectProviderForIp("146.75.100.50")).toBe("fastly");
	});

	it("returns unknown for unmatched IPs", () => {
		expect(detectProviderForIp("8.8.8.8")).toBe("unknown");
		expect(detectProviderForIp("1.1.1.1")).toBe("unknown");
		expect(detectProviderForIp("192.168.1.1")).toBe("unknown");
	});

	it("returns unknown for malformed input", () => {
		expect(detectProviderForIp("not.an.ip")).toBe("unknown");
		expect(detectProviderForIp("")).toBe("unknown");
		expect(detectProviderForIp("999.999.999.999")).toBe("unknown");
	});
});

describe("detectProviderForAddresses", () => {
	it("returns the first known provider", () => {
		expect(
			detectProviderForAddresses(["8.8.8.8", "172.67.166.63"]),
		).toBe("cloudflare");
	});

	it("returns unknown when no addresses match", () => {
		expect(detectProviderForAddresses(["8.8.8.8", "1.1.1.1"])).toBe("unknown");
	});

	it("returns unknown for empty list", () => {
		expect(detectProviderForAddresses([])).toBe("unknown");
	});
});
