// Same-length masking. A credential is overwritten byte for byte with `*`, so a log keeps its
// size, its line breaks and every byte offset after the credential: harnesses that hold the file
// open for appending (Codex), or index into it by byte offset (Codex's thread_turns), never notice.
// JSON escapes, quotes and line breaks inside the range are left alone, so each JSONL line still parses.

const STAR = 0x2a;
const BACKSLASH = 0x5c;
const QUOTE = 0x22;
const LF = 0x0a;
const CR = 0x0d;
const U = 0x75;

/** Masks buf[start, end) in place, sparing the first `keepStart` and last `keepEnd` bytes of the range. Returns how many bytes changed. */
export function maskInPlace(buf: Buffer, start: number, end: number, keepStart = 0, keepEnd = 0): number {
  let backslashes = 0;
  for (let i = start - 1; i >= 0 && buf[i] === BACKSLASH; i--) backslashes++;
  let escaped = backslashes % 2 === 1;
  let hexLeft = 0;
  let changed = 0;
  for (let i = start; i < end; i++) {
    const c = buf[i];
    if (hexLeft > 0) {
      hexLeft--;
      continue;
    }
    if (escaped) {
      escaped = false;
      if (c === U) hexLeft = 4;
      continue;
    }
    if (c === BACKSLASH) {
      escaped = true;
      continue;
    }
    if (c === QUOTE || c === LF || c === CR || c === STAR) continue;
    if (i < start + keepStart || i >= end - keepEnd) continue;
    buf[i] = STAR;
    changed++;
  }
  return changed;
}

const PREFIX = /^(?:[A-Za-z0-9]{1,10}[-_]){1,3}/;
const PEM_HEAD = /^-----BEGIN[ A-Z0-9_-]*-----/;
const PEM_TAIL = /-----END[ A-Z0-9_-]*-----$/;

/**
 * Bytes to leave readable at each end of a credential: a vendor prefix (`ghp_`, `sk-ant-oat01-`)
 * for rules that name a format, the BEGIN and END lines of a private key. Nothing for generic
 * hits and known values, where a prefix could be part of the secret.
 */
export function keepFor(value: string, rule: string): [number, number] {
  const head = PEM_HEAD.exec(value);
  if (head) return [head[0].length, PEM_TAIL.exec(value)?.[0].length ?? 0];
  if (rule.startsWith("generic") || rule.startsWith("known:") || value.length < 20) return [0, 0];
  const prefix = PREFIX.exec(value)?.[0] ?? "";
  return [prefix.length <= value.length / 3 ? Buffer.byteLength(prefix) : 0, 0];
}

/** What a report shows in place of a value: its kept prefix and a few stars. */
export function preview(value: string, rule: string): string {
  if (rule.startsWith("known:")) return `<${rule.slice(6)}>`;
  const [start] = keepFor(value, rule);
  return `${value.slice(0, start)}${"*".repeat(Math.min(8, value.length - start))}`;
}

/** True when the range holds no maskable byte (already scrubbed). */
export function isMasked(buf: Buffer, start: number, end: number, keepStart = 0, keepEnd = 0): boolean {
  const copy = Buffer.from(buf.subarray(Math.max(0, start - 8), end));
  return maskInPlace(copy, start - Math.max(0, start - 8), copy.length, keepStart, keepEnd) === 0;
}
