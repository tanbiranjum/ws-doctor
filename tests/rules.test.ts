import { describe, expect, it } from "vitest";
import { runRules } from "../src/rules/engine.js";
import { allRules } from "../src/rules/index.js";
import {
	makeDns,
	makeHttp,
	makeLibrary,
	makePolling,
	makeTls,
	makeTrace,
	makeWs,
} from "./helpers.js";

/**
 * Each test below exercises one canonical failure mode against the full rule
 * registry and asserts that the right rule wins.
 */

describe("rules — Cloudflare WS toggle off", () => {
	it("fires when CF detected, polling ok, ws silent-hang", () => {
		const trace = makeTrace({
			dns: makeDns("cloudflare", ["172.67.166.63"]),
			tls: makeTls(),
			http: makeHttp({ status: 200 }),
			libraryDetect: makeLibrary("socket.io"),
			polling: makePolling(true),
			wsUpgrade: makeWs("silent-hang"),
		});
		const diagnoses = runRules(trace, allRules);
		const ids = diagnoses.map((d) => d.rule.id);
		expect(ids).toContain("cf.ws-toggle-likely-off");
		// And the Bun fallback also fires (same fingerprint, lower confidence)
		expect(ids).toContain("runtime.bun-bundler-target-node");
		// CF rule outranks Bun rule
		expect(ids.indexOf("cf.ws-toggle-likely-off")).toBeLessThan(
			ids.indexOf("runtime.bun-bundler-target-node"),
		);
	});

	it("does NOT fire CF rule when target is not CF-proxied", () => {
		const trace = makeTrace({
			dns: makeDns("unknown", ["134.199.172.237"]),
			polling: makePolling(true),
			wsUpgrade: makeWs("silent-hang"),
		});
		const diagnoses = runRules(trace, allRules);
		const ids = diagnoses.map((d) => d.rule.id);
		expect(ids).not.toContain("cf.ws-toggle-likely-off");
		expect(ids).toContain("reverse-proxy.drops-upgrade");
	});
});

describe("rules — wrong-host SPA fallback", () => {
	it("fires when http returns HTML with content-disposition=index.html", () => {
		const trace = makeTrace({
			dns: makeDns("cloudflare"),
			http: makeHttp({
				status: 200,
				bodyLooksLike: "html",
				bodyContentType: "text/html; charset=utf-8",
				headers: { "content-disposition": 'inline; filename="index.html"' },
				bodySnippet: "<!DOCTYPE html><html>...",
			}),
			libraryDetect: makeLibrary("socket.io"),
			polling: makePolling(false, 200),
			wsUpgrade: makeWs("silent-hang"),
		});
		const diagnoses = runRules(trace, allRules);
		expect(diagnoses[0]?.rule.id).toBe("wrong-host.spa-fallback");
	});
});

describe("rules — origin reverse proxy drops upgrade", () => {
	it("fires when not behind CF, polling ok, ws silent-hang", () => {
		const trace = makeTrace({
			dns: makeDns("unknown", ["10.0.0.1"]),
			polling: makePolling(true),
			wsUpgrade: makeWs("silent-hang"),
		});
		const diagnoses = runRules(trace, allRules);
		expect(diagnoses.map((d) => d.rule.id)).toContain(
			"reverse-proxy.drops-upgrade",
		);
	});
});

describe("rules — upstream unreachable (5xx)", () => {
	it("fires on 502 Bad Gateway from ws upgrade", () => {
		const trace = makeTrace({
			dns: makeDns("unknown"),
			wsUpgrade: makeWs("rejected", { responseStatus: 502 }),
		});
		const diagnoses = runRules(trace, allRules);
		expect(diagnoses.map((d) => d.rule.id)).toContain(
			"reverse-proxy.upstream-unreachable",
		);
	});

	it("fires on 503 / 504 too", () => {
		for (const status of [503, 504]) {
			const trace = makeTrace({
				wsUpgrade: makeWs("rejected", { responseStatus: status }),
			});
			const diagnoses = runRules(trace, allRules);
			expect(diagnoses.map((d) => d.rule.id)).toContain(
				"reverse-proxy.upstream-unreachable",
			);
		}
	});
});

describe("rules — HTTPS redirect", () => {
	it("fires on redirected ws upgrade", () => {
		const trace = makeTrace({
			dns: makeDns("unknown"),
			wsUpgrade: makeWs("redirected"),
		});
		const diagnoses = runRules(trace, allRules);
		expect(diagnoses.map((d) => d.rule.id)).toContain(
			"reverse-proxy.https-redirect",
		);
	});
});

describe("rules — Cloudflare challenge", () => {
	it("fires when ws upgrade returns 403 from cloudflare", () => {
		const trace = makeTrace({
			dns: makeDns("cloudflare"),
			wsUpgrade: makeWs("rejected", {
				responseStatus: 403,
				responseHeaders: { server: "cloudflare" },
			}),
		});
		const diagnoses = runRules(trace, allRules);
		expect(diagnoses.map((d) => d.rule.id)).toContain(
			"cf.challenge-blocking-upgrade",
		);
	});

	it("fires when cf-mitigated header is present", () => {
		const trace = makeTrace({
			dns: makeDns("cloudflare"),
			wsUpgrade: makeWs("rejected", {
				responseStatus: 403,
				responseHeaders: { "cf-mitigated": "challenge" },
			}),
		});
		const diagnoses = runRules(trace, allRules);
		expect(diagnoses.map((d) => d.rule.id)).toContain(
			"cf.challenge-blocking-upgrade",
		);
	});
});

describe("rules — TLS cert mismatch", () => {
	it("fires when cert SAN list doesn't include target host", () => {
		const trace = makeTrace({
			dns: makeDns("unknown"),
			tls: makeTls({
				cert: {
					subject: "CN=other.com",
					issuer: "CN=Let's Encrypt",
					subjectAltNames: ["other.com"],
					validFrom: "2026-01-01",
					validTo: "2026-04-01",
					matchesHost: false,
				},
			}),
		});
		const diagnoses = runRules(trace, allRules);
		expect(diagnoses.map((d) => d.rule.id)).toContain("tls.cert-host-mismatch");
	});
});

describe("rules — Socket.IO CORS rejection", () => {
	it("fires when polling works, ws gets 502, AND we sent an Origin", () => {
		const trace = makeTrace({
			dns: makeDns("unknown"),
			libraryDetect: makeLibrary("socket.io"),
			polling: makePolling(true),
			wsUpgrade: makeWs("rejected", {
				responseStatus: 502,
				originSent: "https://stage-api.example.com",
			}),
		});
		const diagnoses = runRules(trace, allRules);
		expect(diagnoses.map((d) => d.rule.id)).toContain(
			"socketio.cors-likely-rejecting",
		);
	});

	it("does NOT fire when no Origin was sent", () => {
		const trace = makeTrace({
			dns: makeDns("unknown"),
			libraryDetect: makeLibrary("socket.io"),
			polling: makePolling(true),
			wsUpgrade: makeWs("rejected", {
				responseStatus: 502,
				originSent: null,
			}),
		});
		const diagnoses = runRules(trace, allRules);
		expect(diagnoses.map((d) => d.rule.id)).not.toContain(
			"socketio.cors-likely-rejecting",
		);
		// Still fires the upstream-unreachable rule (legitimate 502)
		expect(diagnoses.map((d) => d.rule.id)).toContain(
			"reverse-proxy.upstream-unreachable",
		);
	});

	it("does NOT fire on non-Socket.IO targets", () => {
		const trace = makeTrace({
			libraryDetect: makeLibrary("raw-ws"),
			wsUpgrade: makeWs("rejected", {
				responseStatus: 502,
				originSent: "https://example.com",
			}),
		});
		const diagnoses = runRules(trace, allRules);
		expect(diagnoses.map((d) => d.rule.id)).not.toContain(
			"socketio.cors-likely-rejecting",
		);
	});
});

describe("rules — happy path", () => {
	it("only auth hint fires when everything succeeds", () => {
		const trace = makeTrace({
			dns: makeDns("cloudflare"),
			tls: makeTls(),
			http: makeHttp({ status: 200 }),
			libraryDetect: makeLibrary("socket.io"),
			polling: makePolling(true),
			wsUpgrade: makeWs("switching-protocols"),
		});
		const diagnoses = runRules(trace, allRules);
		// On a clean trace, the only diagnostic that could fire is the
		// post-handshake auth hint. CF/proxy/runtime rules require ws to fail.
		const ids = diagnoses.map((d) => d.rule.id);
		expect(ids).not.toContain("cf.ws-toggle-likely-off");
		expect(ids).not.toContain("reverse-proxy.drops-upgrade");
		expect(ids).not.toContain("runtime.bun-bundler-target-node");
	});
});
