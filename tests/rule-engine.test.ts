import { describe, expect, it } from "vitest";
import { runRules } from "../src/rules/engine.js";
import type { Rule } from "../src/types.js";
import { makeTrace } from "./helpers.js";

describe("rule engine", () => {
	it("returns empty when no rules match", () => {
		const rules: Rule[] = [
			{
				id: "test.never-matches",
				title: "no-op",
				confidence: 1,
				match: () => false,
				cause: "",
				remediation: [],
			},
		];
		const diagnoses = runRules(makeTrace(), rules);
		expect(diagnoses).toEqual([]);
	});

	it("returns matching rules in descending confidence order", () => {
		const rules: Rule[] = [
			{
				id: "a",
				title: "A",
				confidence: 0.3,
				match: () => true,
				cause: "a",
				remediation: [],
			},
			{
				id: "b",
				title: "B",
				confidence: 0.9,
				match: () => true,
				cause: "b",
				remediation: [],
			},
			{
				id: "c",
				title: "C",
				confidence: 0.6,
				match: () => true,
				cause: "c",
				remediation: [],
			},
		];
		const diagnoses = runRules(makeTrace(), rules);
		expect(diagnoses.map((d) => d.rule.id)).toEqual(["b", "c", "a"]);
	});

	it("swallows thrown errors from rules without breaking others", () => {
		const rules: Rule[] = [
			{
				id: "throws",
				title: "throws",
				confidence: 1,
				match: () => {
					throw new Error("buggy rule");
				},
				cause: "",
				remediation: [],
			},
			{
				id: "ok",
				title: "ok",
				confidence: 0.5,
				match: () => true,
				cause: "ok",
				remediation: [],
			},
		];
		const diagnoses = runRules(makeTrace(), rules);
		expect(diagnoses.map((d) => d.rule.id)).toEqual(["ok"]);
	});
});
