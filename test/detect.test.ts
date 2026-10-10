import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { afterAll, describe, expect, it } from "vitest";
import { gitleaks, knownValues, locate } from "../src/detect.ts";

const dir = mkdtempSync(join(tmpdir(), "agent-scrub-detect-"));
afterAll(() => rmSync(dir, { recursive: true, force: true }));

describe("detection", () => {
  it("does not take commit SHAs for Sourcegraph tokens", async () => {
    const buf = Buffer.from("sourcegraph\ncommit 0123456789abcdef0123456789abcdef01234567\n");
    const findings = await gitleaks("gitleaks", [buf], dir);
    expect(locate(buf, findings, new Map())).toEqual([]);
  });

  it("reads credentials, not settings, from auth files", () => {
    const file = join(dir, "mcp-auth.json");
    const token = "tok_9fQ2xLm7Rz4Kp1Wv8Ns3Yb6";
    writeFileSync(file, JSON.stringify({ server: { token_endpoint_auth_methods_supported: "client_secret_post", tokens: { access_token: token, token_type: "Bearer" } } }));
    const known = knownValues([], [file], {});
    expect([...known.keys()]).toEqual([token]);
  });
});
