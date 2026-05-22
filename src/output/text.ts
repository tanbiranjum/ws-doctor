/**
 * Text output formatter — colored, line-by-line summary of probe results
 * followed by ranked diagnoses.
 *
 * Honors NO_COLOR (via picocolors default behavior) and a `noColor` option.
 */

import pc from "picocolors";
import type { Diagnosis, ProbeResult, Trace } from "../types.js";

interface RenderOptions {
	verbose?: boolean;
	noColor?: boolean;
}

export function renderText(
	trace: Trace,
	diagnoses: Diagnosis[],
	options: RenderOptions = {},
): string {
	const colors = options.noColor ? noColor() : pc;
	const lines: string[] = [];

	lines.push("");
	lines.push(colors.bold(`ws-doctor`) + colors.dim(`  v0.1.3`));
	lines.push(colors.dim(`Target: `) + trace.target.rawUrl);
	if (trace.directOrigin) {
		lines.push(
			colors.dim(`Direct origin: `) +
				`${trace.directOrigin.host}:${trace.directOrigin.port}`,
		);
	}
	lines.push("");

	// --- Probes section ---
	lines.push(colors.bold("Probes"));
	const probeOrder: Array<keyof Trace["probes"]> = [
		"dns",
		"tls",
		"http",
		"libraryDetect",
		"polling",
		"wsUpgrade",
	];

	for (const key of probeOrder) {
		const probe = trace.probes[key];
		if (!probe) continue;
		lines.push(renderProbe(probe, colors, options.verbose ?? false));
	}

	lines.push("");

	// --- Diagnoses section ---
	if (diagnoses.length === 0) {
		const ws = trace.probes.wsUpgrade;
		if (ws?.details.outcomeKind === "switching-protocols") {
			lines.push(
				colors.green(colors.bold("✓ WebSocket upgrade succeeded.")) +
					" The path through DNS/TLS/HTTP/proxy/runtime is clean.",
			);
		} else {
			lines.push(
				colors.yellow(
					"No diagnostic rules matched. The trace above contains the raw observations; you may need to file a new rule for this failure mode.",
				),
			);
		}
		lines.push("");
		return lines.join("\n");
	}

	lines.push(colors.bold("Diagnosis"));
	lines.push(
		colors.dim(
			`Ranked by rule-declared confidence. Higher = more likely root cause.`,
		),
	);
	lines.push("");

	diagnoses.forEach((d, idx) => {
		const num = `${idx + 1}.`;
		const pct = `(${Math.round(d.rule.confidence * 100)}%)`;
		lines.push(
			`${colors.bold(num)} ${colors.bold(d.rule.title)} ${colors.dim(pct)}`,
		);
		lines.push(`   ${colors.dim("→")} ${d.rule.cause}`);
		if (d.rule.remediation.length > 0) {
			lines.push(`   ${colors.bold("Try:")}`);
			for (const step of d.rule.remediation) {
				lines.push(`   ${colors.dim("•")} ${step}`);
			}
		}
		if (d.rule.references && d.rule.references.length > 0) {
			lines.push(`   ${colors.bold("References:")}`);
			for (const ref of d.rule.references) {
				lines.push(`   ${colors.dim("•")} ${colors.cyan(ref)}`);
			}
		}
		lines.push("");
	});

	return lines.join("\n");
}

function renderProbe(
	probe: ProbeResult,
	colors: Colorizer,
	verbose: boolean,
): string {
	const icon =
		probe.outcome === "ok"
			? colors.green("✓")
			: probe.outcome === "fail"
				? colors.red("✗")
				: colors.dim("○");

	const phase = colors.dim(`[${probe.phase.padEnd(14)}]`);
	const duration = colors.dim(`${probe.durationMs}ms`.padStart(6));
	let head = `${icon} ${phase} ${probe.summary} ${duration}`;
	if (probe.error) {
		head += `\n    ${colors.dim("error:")} ${colors.red(probe.error)}`;
	}

	if (!verbose) return head;

	// Verbose: include details (compact JSON)
	const details = JSON.stringify(probe.details ?? {}, null, 2)
		.split("\n")
		.map((line) => `    ${colors.dim(line)}`)
		.join("\n");
	return `${head}\n${details}`;
}

type Colorizer = typeof pc;

function noColor(): Colorizer {
	const identity = (s: string) => s;
	return new Proxy({} as Colorizer, {
		get: () => identity,
	});
}
