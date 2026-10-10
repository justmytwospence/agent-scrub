import { describe as group, expect, it } from "vitest";
import { describe } from "../src/detect.ts";
import { isMasked, keepFor, maskInPlace, preview } from "../src/mask.ts";

group("maskInPlace", () => {
  it("keeps the length and the JSON valid around escapes", () => {
    const line = JSON.stringify({ text: 'key="a\\b\nc\u0001d"' });
    const buf = Buffer.from(line);
    const start = line.indexOf("key");
    maskInPlace(buf, start, line.length - 2);
    expect(buf.length).toBe(line.length);
    expect(() => JSON.parse(buf.toString())).not.toThrow();
    expect(buf.toString()).not.toContain("key");
  });

  it("does not unescape a character when the range starts inside an escape", () => {
    const line = JSON.stringify({ text: "a\nsecretvalue" });
    const buf = Buffer.from(line);
    const start = line.indexOf("nsecret");
    maskInPlace(buf, start, start + 12);
    expect(() => JSON.parse(buf.toString())).not.toThrow();
  });

  it("spares a vendor prefix and the lines of a private key", () => {
    const token = `ghp_${"aB3".repeat(12)}`;
    expect(keepFor(token, "github-pat")).toEqual([4, 0]);
    expect(preview(token, "github-pat")).toBe("ghp_********");
    expect(keepFor(token, "generic-api-key")).toEqual([0, 0]);
    const pem = "-----BEGIN RSA PRIVATE KEY-----\\nMIIabc\\n-----END RSA PRIVATE KEY-----";
    const [head, tail] = keepFor(pem, "private-key");
    expect(pem.slice(0, head)).toBe("-----BEGIN RSA PRIVATE KEY-----");
    expect(pem.slice(pem.length - tail)).toBe("-----END RSA PRIVATE KEY-----");
  });

  it("reports a scrubbed range as masked", () => {
    const buf = Buffer.from("x=abcdef123456");
    expect(isMasked(buf, 2, buf.length)).toBe(false);
    maskInPlace(buf, 2, buf.length);
    expect(isMasked(buf, 2, buf.length)).toBe(true);
  });
});

group("describe", () => {
  it("describes values without revealing them", () => {
    expect(describe("brand_key_account")).toBe("words joined by underscores");
    expect(describe("parent_brand_name=NESTLE")).toBe("words joined by underscores and an equals sign");
    expect(describe("qwen3.6-27b-mlx-instruct-4bit")).toMatch(/^words/);
    expect(describe("brandKeyAccount")).toBe("words");
    expect(describe(`ynab_${"Xk29fLm0Qz".repeat(4)}`)).toMatch(/random-looking/);
    expect(describe("0123456789abcdef0123456789abcdef01234567")).toBe("40 hex characters");
    expect(describe("Zx81QpL0mN3vR7tY2wK9sD4f")).toMatch(/^24 random-looking characters/);
  });
});
