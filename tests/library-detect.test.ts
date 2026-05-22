import { describe, expect, it } from "vitest";
import { probeLibraryDetect } from "../src/probes/library-detect.js";
import { makeTarget } from "./helpers.js";

describe("library detection", () => {
	it("detects Socket.IO via /socket.io/ path", async () => {
		const result = await probeLibraryDetect(
			makeTarget({ rawUrl: "wss://example.com/socket.io/" }),
		);
		expect(result.details.library).toBe("socket.io");
	});

	it("detects Socket.IO via EIO query param", async () => {
		const result = await probeLibraryDetect(
			makeTarget({ rawUrl: "wss://example.com/realtime?EIO=4&transport=websocket" }),
		);
		expect(result.details.library).toBe("socket.io");
	});

	it("falls back to raw-ws for unrecognized URLs", async () => {
		const result = await probeLibraryDetect(
			makeTarget({ rawUrl: "wss://example.com/api/stream" }),
		);
		expect(result.details.library).toBe("raw-ws");
	});

	it("extracts EIO version when present", async () => {
		const result = await probeLibraryDetect(
			makeTarget({ rawUrl: "wss://example.com/socket.io/?EIO=4" }),
		);
		expect(result.details.evidence.eioVersion).toBe("4");
	});
});
