/**
 * Rule engine — pure, stateless. Runs every rule's match() against the trace
 * and returns the matching diagnoses sorted by confidence (descending).
 *
 * Rules are deliberately not "scored" by the engine — each rule self-declares
 * its confidence. This keeps the engine simple and lets contributors reason
 * about their rules in isolation.
 */

import type { Diagnosis, Rule, Trace } from "../types.js";

export function runRules(trace: Trace, rules: Rule[]): Diagnosis[] {
	const matched: Diagnosis[] = [];
	for (const rule of rules) {
		try {
			if (rule.match(trace)) {
				matched.push({ rule, matched: true });
			}
		} catch (err) {
			// A rule should never throw. If it does, swallow and continue —
			// one buggy rule shouldn't break the whole diagnosis.
			console.error(
				`[ws-doctor] rule "${rule.id}" threw during match:`,
				err instanceof Error ? err.message : err,
			);
		}
	}

	matched.sort((a, b) => b.rule.confidence - a.rule.confidence);
	return matched;
}
