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

describe("env files", () => {
  it("expands globs and keeps only credential-named values", async () => {
    const { mkdtempSync, mkdirSync, writeFileSync } = await import("node:fs");
    const { tmpdir } = await import("node:os");
    const { join } = await import("node:path");
    const { globbed } = await import("../src/config.ts");
    const dir = mkdtempSync(join(tmpdir(), "scrub-glob-"));
    const files: Record<string, string> = {
      a: "PLAID_SECRET=f7d3b90794f997e3eb80ee2a809a806x\nDOMAIN=examplehomelab.com\n",
      b: "PLAID_CLIENT_ID=6ae3b90794f997000dda1824\nPLAID_TOKENS={\"bank\":\"access-production-1b2c3d4e-0000-4a4a-9f9f-1234567890ab\"}\n",
    };
    for (const [svc, body] of Object.entries(files)) {
      mkdirSync(join(dir, svc));
      writeFileSync(join(dir, svc, ".env"), body);
    }
    const found = globbed(join(dir, "*", ".env"));
    expect(found).toHaveLength(2);
    const known = knownValues([], [], {}, found);
    expect(known.get("f7d3b90794f997e3eb80ee2a809a806x")).toBe("PLAID_SECRET");
    expect(known.get("6ae3b90794f997000dda1824")).toBe("PLAID_CLIENT_ID");
    expect(known.get("access-production-1b2c3d4e-0000-4a4a-9f9f-1234567890ab")).toBe("PLAID_TOKENS.bank");
    expect(known.has("examplehomelab.com")).toBe(false);
    expect(knownValues(found, [], {}).has("examplehomelab.com")).toBe(true);
    expect(globbed("/plain/path")).toEqual(["/plain/path"]);
  });
});
