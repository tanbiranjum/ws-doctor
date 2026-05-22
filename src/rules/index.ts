/**
 * Rule registry. All shipped rules are imported here and exposed as a flat
 * array consumed by the runner. New rule files are added by appending to
 * this list.
 */

import type { Rule } from "../types.js";
import { cloudflareRules } from "./cloudflare.js";
import { wrongHostRules } from "./wrong-host.js";
import { reverseProxyRules } from "./reverse-proxy.js";
import { runtimeBugRules } from "./runtime-bugs.js";
import { authRules } from "./auth.js";
import { tlsRules } from "./tls-and-cert.js";
import { socketioRules } from "./socketio.js";

export const allRules: Rule[] = [
	...tlsRules,
	...wrongHostRules,
	...cloudflareRules,
	...socketioRules,
	...reverseProxyRules,
	...runtimeBugRules,
	...authRules,
];
