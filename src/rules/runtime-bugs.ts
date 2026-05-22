/**
 * Runtime-bug rules — known issues in specific JS runtimes or bundlers that
 * cause WS upgrade failures that look identical to network-level problems.
 *
 * These rules fire as additional suspects when the symptom matches and
 * there's no stronger signal. They're "have you checked X?" prompts — not
 * confident accusations.
 */

import type { Rule } from "../types.js";

const bunNodeTargetBundlerBug: Rule = {
	id: "runtime.bun-bundler-target-node",
	title: "Possible Bun.build target:'node' bug (if backend is Bun-bundled)",
	confidence: 0.25,
	match: (trace) => {
		const ws = trace.probes.wsUpgrade;
		const polling = trace.probes.polling;
		// Fingerprint: polling works, WS upgrade silently hangs. Same fingerprint
		// as CF-WS-off and origin-proxy-drops-upgrade — we list this as a lower-
		// confidence sibling so users who don't find the CF/proxy fixes apply
		// have a next thing to check.
		return (
			polling?.details.openPacketReceived === true &&
			ws?.details.outcomeKind === "silent-hang"
		);
	},
	cause:
		"If the backend is running on Bun and bundled with `Bun.build({ target: 'node' })`, the bundled output's `node:http` upgrade response is silently dropped. Polling still works because it doesn't use the `upgrade` event.",
	remediation: [
		"If applicable to your stack: check your build script for `target: 'node'` in `Bun.build`. Change it to `target: 'bun'` and rebuild.",
		"If `target: 'bun'` causes other build errors (e.g. Mongoose 'readonly property'), try adding the offending package to the `external` array instead of switching targets.",
		"NOT applicable if your backend runs on Node.js or Deno or your bundler is webpack/esbuild/rollup.",
	],
	references: [
		"https://github.com/oven-sh/bun/issues/9882",
	],
};

export const runtimeBugRules: Rule[] = [bunNodeTargetBundlerBug];
