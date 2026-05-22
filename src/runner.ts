/**
 * Runner — orchestrates the probes in order, builds the Trace, and feeds it
 * to the rule engine.
 *
 * Probe ordering matters:
 *   1. DNS — must succeed before anything else can talk to the host
 *   2. TLS — must succeed before HTTP/WS can speak over the channel
 *   3. HTTP — sanity that the host responds to plain HTTP
 *   4. Library detect — informs how polling/WS probes phrase requests
 *   5. Polling — establishes whether the application stack works at all
 *   6. WS upgrade — the actual test, with maximum context if it fails
 *
 * Each probe is independently failure-tolerant. Downstream probes still run
 * if an earlier one fails (we want as much diagnostic data as possible),
 * unless DNS itself can't resolve.
 */

import { probeDns } from "./probes/dns.js";
import { probeTls } from "./probes/tls.js";
import { probeHttp } from "./probes/http.js";
import { probeLibraryDetect } from "./probes/library-detect.js";
import { probePolling } from "./probes/polling.js";
import { probeWsUpgrade } from "./probes/ws-upgrade.js";
import { runRules } from "./rules/engine.js";
import { allRules } from "./rules/index.js";
import type { RunResult, RunnerOptions, Trace } from "./types.js";

export async function run(options: RunnerOptions): Promise<RunResult> {
	const startedAt = new Date().toISOString();
	const startTime = performance.now();

	const trace: Trace = {
		target: options.target,
		startedAt,
		totalDurationMs: 0,
		probes: {},
		directOrigin: options.directOrigin,
	};

	// 1. DNS
	const dns = await probeDns(options.target);
	trace.probes.dns = dns;
	if (dns.outcome === "fail") {
		trace.totalDurationMs = Math.round(performance.now() - startTime);
		const diagnoses = runRules(trace, allRules);
		return { trace, diagnoses };
	}

	// 2. TLS (skipped if non-TLS target)
	const tls = await probeTls(
		options.target,
		options.directOrigin
			? {
					host: options.directOrigin.host,
					port: options.directOrigin.port,
					servername: options.target.host,
				}
			: undefined,
		options.timeoutMs,
	);
	trace.probes.tls = tls;

	// 3. HTTP reachability
	const http = await probeHttp({
		target: options.target,
		timeoutMs: options.timeoutMs,
		directOrigin: options.directOrigin,
	});
	trace.probes.http = http;

	// 4. Library detection
	const libraryDetect = await probeLibraryDetect(options.target);
	trace.probes.libraryDetect = libraryDetect;

	// 5. Polling
	const polling = await probePolling({
		target: options.target,
		libraryDetect,
		timeoutMs: options.timeoutMs,
		directOrigin: options.directOrigin,
	});
	trace.probes.polling = polling;

	// 6. WS upgrade — the headline test
	const wsUpgrade = await probeWsUpgrade({
		target: options.target,
		timeoutMs: options.timeoutMs,
		directOrigin: options.directOrigin,
	});
	trace.probes.wsUpgrade = wsUpgrade;

	trace.totalDurationMs = Math.round(performance.now() - startTime);

	const diagnoses = runRules(trace, allRules);
	return { trace, diagnoses };
}
