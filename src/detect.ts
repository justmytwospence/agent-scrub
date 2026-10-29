// Finding credentials: gitleaks' rules over the new content, plus the exact values of the
// credentials this machine holds (no rule knows the format of every key).

import { spawn } from "node:child_process";
import { existsSync, readFileSync } from "node:fs";
import { basename } from "node:path";
import { fileURLToPath } from "node:url";
import { keepFor, maskInPlace } from "./mask.ts";

export interface Finding {
  rule: string;
  secret: string;
  match: string;
}

/** A credential at [start, end) of a segment's bytes. `generic` hits still need triage. */
export interface Hit {
  start: number;
  end: number;
  rule: string;
  value: string;
  generic: boolean;
}

const CHUNK_BYTES = 16 * 1024 * 1024;
const GITLEAKS_CONFIG = fileURLToPath(new URL("../gitleaks.toml", import.meta.url));

/** Runs `gitleaks stdin` over the texts, in chunks of about 16 MB, a few at a time. */
export async function gitleaks(bin: string, texts: Buffer[], cwd: string, concurrency = 4): Promise<Finding[]> {
  const chunks: Buffer[][] = [[]];
  let size = 0;
  for (const text of texts) {
    if (size > 0 && size + text.length > CHUNK_BYTES) {
      chunks.push([]);
      size = 0;
    }
    chunks[chunks.length - 1].push(text, Buffer.from("\n"));
    size += text.length + 1;
  }
  const findings: Finding[] = [];
  let next = 0;
  const worker = async () => {
    while (next < chunks.length) {
      const chunk = chunks[next++];
      if (chunk.length > 0) findings.push(...(await gitleaksOnce(bin, Buffer.concat(chunk), cwd)));
    }
  };
  await Promise.all(Array.from({ length: Math.min(concurrency, chunks.length) }, worker));
  return findings;
}

function gitleaksOnce(bin: string, input: Buffer, cwd: string): Promise<Finding[]> {
  return new Promise((resolve, reject) => {
    // Decoding stays off: a secret found inside base64 is not in the file as written, so it could not be masked.
    const args = ["stdin", "-c", GITLEAKS_CONFIG, "--no-banner", "-l", "error", "--exit-code", "0", "--max-decode-depth", "0", "-f", "json", "-r", "-"];
    const child = spawn(bin, args, { cwd, stdio: ["pipe", "pipe", "pipe"] });
    const out: Buffer[] = [];
    const err: Buffer[] = [];
    child.stdout.on("data", (d: Buffer) => out.push(d));
    child.stderr.on("data", (d: Buffer) => err.push(d));
    child.on("error", reject);
    child.on("close", (code) => {
      if (code !== 0) return reject(new Error(`gitleaks exited ${code}: ${Buffer.concat(err).toString().slice(0, 500)}`));
      const text = Buffer.concat(out).toString().trim();
      const raw = (text ? JSON.parse(text) : []) as { RuleID: string; Secret: string; Match: string }[];
      resolve(raw.map((f) => ({ rule: f.RuleID, secret: f.Secret, match: f.Match })));
    });
    child.stdin.on("error", () => {});
    child.stdin.end(input);
  });
}

const KNOWN_MIN = 12;
/** Auth-file keys that hold a credential: access_token, refreshToken, api_key, client_secret, ... (not token_type or token_endpoint_auth_methods_supported). */
const TOKEN_KEY = /(token|key|secret|password)$/i;

/** The credentials this machine holds, value -> name: KEY=VALUE files, token-like leaves of auth JSON, and *_KEY/_TOKEN/_SECRET variables. */
/** Variable names in service env files that hold a credential. */
export const CREDENTIAL_NAME = /(KEY|TOKEN|SECRET|PASSWORD|PASS|CLIENT_ID)$/i;

export function knownValues(secretsFiles: string[], authFiles: string[], env: NodeJS.ProcessEnv = process.env, envFiles: string[] = []): Map<string, string> {
  const known = new Map<string, string>();
  const add = (value: unknown, name: string) => {
    if (typeof value === "string" && value.length >= KNOWN_MIN && !/\s|:\/\//.test(value) && entropy(value) >= 3) known.set(value, name);
  };
  const readEnv = (file: string, only?: RegExp) => {
    if (!existsSync(file)) return;
    for (const line of readFileSync(file, "utf8").split("\n")) {
      const m = /^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$/.exec(line);
      if (m && (!only || only.test(m[1]))) add(m[2].replace(/^(['"])(.*)\1$/, "$2"), m[1]);
    }
  };
  for (const file of secretsFiles) readEnv(file);
  for (const file of envFiles) readEnv(file, CREDENTIAL_NAME);
  for (const file of authFiles) {
    if (!existsSync(file)) continue;
    let json: unknown;
    try {
      json = JSON.parse(readFileSync(file, "utf8"));
    } catch {
      continue;
    }
    const walk = (node: unknown, key: string) => {
      if (typeof node === "string") {
        if (TOKEN_KEY.test(key)) add(node, `${basename(file)}:${key}`);
      } else if (node && typeof node === "object") {
        for (const [k, v] of Object.entries(node)) walk(v, Array.isArray(node) ? key : k);
      }
    };
    walk(json, "");
  }
  for (const [name, value] of Object.entries(env)) {
    if (/(KEY|TOKEN|SECRET|PASSWORD)$/.test(name)) add(value, name);
  }
  return known;
}

/** Shannon entropy in bits per character. */
export function entropy(s: string): number {
  const counts = new Map<string, number>();
  for (const c of s) counts.set(c, (counts.get(c) ?? 0) + 1);
  let h = 0;
  for (const n of counts.values()) h -= (n / s.length) * Math.log2(n / s.length);
  return h;
}

function occurrences(buf: Buffer, needle: Buffer, from = 0, to = buf.length): number[] {
  const at: number[] = [];
  for (let i = buf.indexOf(needle, from); i !== -1 && i + needle.length <= to; i = buf.indexOf(needle, i + needle.length)) at.push(i);
  return at;
}

const MIN_VALUE = 8;
/** A commit SHA or a sha256 digest: never masked everywhere it appears, and triaged like a generic hit. */
const HASH = /^(?:[0-9a-f]{40}|[0-9a-f]{64})$/i;

/**
 * Locates credentials in one segment. Values from format rules and known values are masked
 * wherever they appear; a generic value only where gitleaks matched it (its keyword context),
 * so a short password does not mask every unrelated occurrence of the same word.
 */
export function locate(buf: Buffer, findings: Finding[], known: Map<string, string>): Hit[] {
  const hits: Hit[] = [];
  const strong = new Map<string, string>();
  for (const f of findings) {
    if (f.secret.length >= MIN_VALUE && !f.rule.startsWith("generic") && !HASH.test(f.secret)) strong.set(f.secret, f.rule);
  }
  for (const [value, name] of known) strong.set(value, `known:${name}`);
  for (const [value, rule] of strong) {
    const needle = Buffer.from(value);
    for (const at of occurrences(buf, needle)) hits.push({ start: at, end: at + needle.length, rule, value, generic: false });
  }
  for (const f of findings) {
    // Generic hits, and hash-shaped values from any rule, count only where gitleaks matched them.
    if (!(f.rule.startsWith("generic") || HASH.test(f.secret)) || f.secret.length < MIN_VALUE || strong.has(f.secret)) continue;
    const idx = f.match.indexOf(f.secret);
    if (idx < 0) continue;
    const match = Buffer.from(f.match);
    const offset = Buffer.byteLength(f.match.slice(0, idx));
    const len = Buffer.byteLength(f.secret);
    for (const at of occurrences(buf, match)) {
      hits.push({ start: at + offset, end: at + offset + len, rule: f.rule, value: f.secret, generic: true });
    }
  }
  return merge(hits, buf);
}

/** Drops hits already masked and overlapping duplicates, preferring the more specific rule. */
function merge(hits: Hit[], buf: Buffer): Hit[] {
  const rank = (h: Hit) => (h.generic ? 2 : h.rule.startsWith("known:") ? 1 : 0);
  hits.sort((a, b) => a.start - b.start || rank(a) - rank(b) || b.end - a.end);
  const out: Hit[] = [];
  for (const h of hits) {
    const last = out[out.length - 1];
    if (last && h.start < last.end) {
      if (h.end > last.end && rank(h) < rank(last)) out[out.length - 1] = h;
      continue;
    }
    const [ks, ke] = keepFor(h.value, h.rule);
    const copy = Buffer.from(buf.subarray(Math.max(0, h.start - 8), h.end));
    if (maskInPlace(copy, h.start - Math.max(0, h.start - 8), copy.length, ks, ke) === 0) continue;
    out.push(h);
  }
  return out;
}

/** A copy of `buf` with every hit masked: what may leave the machine (Jev's context) is built from this. */
export function redacted(buf: Buffer, hits: { start: number; end: number }[]): Buffer {
  const copy = Buffer.from(buf);
  for (const h of hits) maskInPlace(copy, h.start, h.end);
  return copy;
}

/** The text around a hit with the value replaced by <VALUE>, built from a redacted copy. */
export function contextOf(redactedBuf: Buffer, start: number, end: number, before = 100, after = 60): string {
  const head = redactedBuf.subarray(Math.max(0, start - before), start).toString("utf8");
  const tail = redactedBuf.subarray(end, Math.min(redactedBuf.length, end + after)).toString("utf8");
  return `${head}<VALUE>${tail}`;
}

/** Plain-language features of a value, so Jev can judge it without seeing it. */
export function describe(value: string): string {
  if (/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i.test(value)) return "a UUID";
  if (/^[0-9a-f]+$/i.test(value)) return `${value.length} hex characters`;
  if (/^\d+$/.test(value)) return `${value.length} digits`;
  // Pieces between separators and camelCase humps: a word (one case, a vowel, no long consonant
  // run, maybe a version number after it), a short piece that says nothing either way (`27b`,
  // `mlx`, `v2`), or the rest, which is what random tokens are made of.
  const pieces = value.split(/[_\-./:=+@,]+|(?<=[a-z])(?=[A-Z])/).filter(Boolean);
  let wordChars = 0;
  let otherChars = 0;
  for (const piece of pieces) {
    const letters = piece.replace(/\d+$/, "");
    const word =
      /^(?:[a-z]{3,}|[A-Z]{3,}|[A-Z][a-z]{2,})$/.test(letters) && /[aeiouy]/i.test(letters) && !/[^aeiouy]{5,}/i.test(letters);
    if (word) wordChars += piece.length;
    else if (piece.length > 4) otherChars += piece.length;
  }
  const names: Record<string, string> = { _: "underscores", "-": "hyphens", ".": "dots", "/": "slashes", ":": "colons", "=": "an equals sign", "+": "plus signs", "@": "an at sign", ",": "commas" };
  const seps = [...new Set(value.match(/[_\-./:=+@,]/g) ?? [])].map((c) => names[c]);
  const joined = seps.length ? ` joined by ${seps.join(" and ")}` : "";
  if (wordChars > 0 && wordChars >= 3 * otherChars) return `words${joined}`;
  const classes = [/[A-Z]/.test(value) && "upper", /[a-z]/.test(value) && "lower", /\d/.test(value) && "digits", /[^A-Za-z0-9]/.test(value) && "symbols"].filter(Boolean);
  return `${value.length} random-looking characters (${classes.join(", ")})`;
}

