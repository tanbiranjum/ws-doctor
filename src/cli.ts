#!/usr/bin/env node
/**
 * ws-doctor CLI entrypoint.
 *
 * Parses args, builds a Target from the user-supplied URL, runs the probe
 * pipeline, prints a report.
 *
 * Exit codes:
 *   0 — WS upgrade succeeded
 *   1 — WS upgrade failed (any failure mode)
 *   2 — invalid usage / argument error
 */

import { Command, InvalidArgumentError } from "commander";
import { run } from "./runner.js";
import { renderText } from "./output/text.js";
import type { Target } from "./types.js";

interface CliOptions {
	timeout: number;
	verbose: boolean;
	color: boolean;
	direct?: string;
	origin?: string;
}

const program = new Command();

program
	.name("ws-doctor")
	.description(
		"Diagnose WebSocket connection failures across DNS, TLS, HTTP, proxy, and application layers.",
	)
	.argument(
		"<url>",
		"WebSocket URL to test (e.g. wss://api.example.com/socket.io/?EIO=4&transport=websocket)",
	)
	.option(
		"-t, --timeout <ms>",
		"per-probe timeout in milliseconds",
		(v) => {
			const n = Number(v);
			if (!Number.isInteger(n) || n <= 0) {
				throw new InvalidArgumentError("must be a positive integer");
			}
			return n;
		},
		10_000,
	)
	.option(
		"--direct <host:port>",
		"bypass DNS and connect to a specific origin (useful for testing behind CDNs)",
	)
	.option(
		"--origin <url>",
		"send an Origin header on the WS upgrade (omitted by default; set this if the server's CORS allow-list requires a specific frontend origin)",
	)
	.option("-v, --verbose", "show full probe details", false)
	.option("--no-color", "disable colored output")
	.version("0.1.3", "-V, --version", "print the version")
	.showHelpAfterError()
	.action(async (url: string, options: CliOptions) => {
		const target = parseTarget(url);
		if (!target) {
			console.error(
				`error: could not parse URL "${url}". Expected wss:// or ws://.`,
			);
			process.exit(2);
		}

		const directOrigin = options.direct ? parseDirect(options.direct) : null;
		if (options.direct && !directOrigin) {
			console.error(
				`error: --direct must be in the form host:port, got "${options.direct}"`,
			);
			process.exit(2);
		}

		const { trace, diagnoses } = await run({
			target,
			timeoutMs: options.timeout,
			directOrigin,
			verbose: options.verbose,
			origin: options.origin ?? null,
		});

		process.stdout.write(
			renderText(trace, diagnoses, {
				verbose: options.verbose,
				noColor: !options.color,
			}),
		);

		const ws = trace.probes.wsUpgrade;
		if (ws?.details.outcomeKind === "switching-protocols") {
			process.exit(0);
		}
		process.exit(1);
	});

program.parseAsync(process.argv).catch((err) => {
	console.error(err instanceof Error ? err.message : err);
	process.exit(2);
});

/**
 * Parse the user-supplied URL into a Target. Accepts ws:, wss:, http:, https:
 * (we coerce http/https to ws/wss for convenience). Returns null on failure.
 */
function parseTarget(raw: string): Target | null {
	let url: URL;
	try {
		url = new URL(raw);
	} catch {
		return null;
	}

	// Coerce http(s):// to ws(s)://
	if (url.protocol === "http:") url.protocol = "ws:";
	else if (url.protocol === "https:") url.protocol = "wss:";

	if (url.protocol !== "ws:" && url.protocol !== "wss:") return null;

	const secure = url.protocol === "wss:";
	const port = url.port ? Number(url.port) : secure ? 443 : 80;
	const path = url.pathname || "/";
	const search = url.search || "";

	return {
		rawUrl: raw,
		url,
		host: url.hostname,
		port,
		secure,
		pathWithQuery: `${path}${search}`,
		path,
	};
}

function parseDirect(s: string): { host: string; port: number } | null {
	const idx = s.lastIndexOf(":");
	if (idx <= 0 || idx === s.length - 1) return null;
	const host = s.slice(0, idx);
	const port = Number(s.slice(idx + 1));
	if (!Number.isInteger(port) || port <= 0 || port > 65535) return null;
	return { host, port };
}
