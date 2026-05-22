/**
 * Programmatic API. Most users will use the CLI, but exposing `run` and the
 * core types lets ws-doctor be embedded in CI checks, health probes, etc.
 */

export { run } from "./runner.js";
export { renderText } from "./output/text.js";
export { allRules } from "./rules/index.js";
export { runRules } from "./rules/engine.js";
export type {
	Target,
	Trace,
	ProbeResult,
	Rule,
	Diagnosis,
	RunResult,
	RunnerOptions,
	DnsResult,
	TlsResult,
	HttpResult,
	LibraryDetectResult,
	PollingResult,
	WsUpgradeResult,
	WsUpgradeOutcomeKind,
	DetectedLibrary,
	DetectedProvider,
} from "./types.js";
