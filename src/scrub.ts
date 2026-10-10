// Masks every credential in one session's log, in place.

import { closeSync, openSync, readFileSync, readSync, writeSync } from "node:fs";
import { availableParallelism, tmpdir } from "node:os";
import { DatabaseSync } from "node:sqlite";
import type { Config } from "./config.ts";
import { contextOf, describe, gitleaks, type Hit, knownValues, locate, redacted } from "./detect.ts";
import { type Ask, triage } from "./jev.ts";
import { keepFor, maskInPlace } from "./mask.ts";
import type { Session, Source } from "./session.ts";

export interface Result {
  masked: number;
  /** rule -> count; a known value's rule is `known:<NAME>`. */
  rules: Map<string, number>;
  /** Files and tables that changed. */
  changed: Set<string>;
  scannedBytes: number;
}

interface Segment {
  source: Source;
  /** Byte offset in the file, or the row's rowid. */
  at: number;
  buf: Buffer;
  hits: Hit[];
}

function readFile(path: string): Buffer {
  return readFileSync(path);
}

function segmentsOf(source: Source, dbs: Map<string, DatabaseSync>): Segment[] {
  if (source.kind === "file") {
    const buf = readFile(source.path);
    if (!source.lines) return buf.subarray(0, 4096).includes(0) ? [] : [{ source, at: 0, buf, hits: [] }];
    // A shared history file: only the lines that belong to this session.
    const out: Segment[] = [];
    const id = Buffer.from(source.lines);
    for (let start = 0; start < buf.length; ) {
      let end = buf.indexOf(0x0a, start);
      if (end === -1) end = buf.length;
      const line = buf.subarray(start, end);
      if (line.includes(id)) out.push({ source, at: start, buf: line, hits: [] });
      start = end + 1;
    }
    return out;
  }
  let db = dbs.get(source.db);
  if (!db) {
    db = new DatabaseSync(source.db);
    db.exec("PRAGMA busy_timeout = 5000");
    dbs.set(source.db, db);
  }
  if (!db.prepare("SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?").get(source.table)) return [];
  const rows = db.prepare(`SELECT rowid AS rid, ${source.col} AS txt FROM ${source.table} WHERE ${source.key} = ?`).all(source.value) as { rid: number; txt: unknown }[];
  return rows.filter((r) => typeof r.txt === "string").map((r) => ({ source, at: r.rid, buf: Buffer.from(r.txt as string), hits: [] }));
}

/** Finds and masks the credentials in a session. A dry run reports what it would mask. */
export async function scrub(session: Session, config: Config, opts: { dryRun?: boolean; ask?: Ask; log?: (s: string) => void } = {}): Promise<Result> {
  const dbs = new Map<string, DatabaseSync>();
  const result: Result = { masked: 0, rules: new Map(), changed: new Set(), scannedBytes: 0 };
  try {
    const segments = session.sources.flatMap((s) => segmentsOf(s, dbs));
    result.scannedBytes = segments.reduce((n, s) => n + s.buf.length, 0);
    if (segments.length === 0) return result;
    const known = knownValues(config.secretsFiles, config.authFiles);
    const findings = await gitleaks(config.gitleaks, segments.map((s) => s.buf), tmpdir(), Math.max(2, Math.floor(availableParallelism() / 2)));
    for (const seg of segments) seg.hits = locate(seg.buf, findings, known);

    // Generic hits (a keyword before a random-looking value) are kept only if they look like credentials.
    const generic = segments.flatMap((seg) => seg.hits.filter((h) => h.generic).map((hit) => ({ seg, hit })));
    if (generic.length > 0) {
      const keep = await keepGeneric(generic, config, opts);
      for (const seg of segments) seg.hits = seg.hits.filter((h) => !h.generic || keep.has(h));
    }

    for (const seg of segments) {
      if (seg.hits.length === 0) continue;
      const masked = Buffer.from(seg.buf);
      for (const h of seg.hits) {
        const [ks, ke] = keepFor(h.value, h.rule);
        maskInPlace(masked, h.start, h.end, ks, ke);
        result.rules.set(h.rule, (result.rules.get(h.rule) ?? 0) + 1);
        result.masked++;
      }
      const where = seg.source.kind === "file" ? seg.source.path : `${seg.source.db}#${seg.source.table}`;
      result.changed.add(where);
      if (!opts.dryRun && !write(seg, masked, dbs)) opts.log?.(`${where} changed while scrubbing; run again`);
    }
    return result;
  } finally {
    for (const db of dbs.values()) db.close();
  }
}

async function keepGeneric(generic: { seg: Segment; hit: Hit }[], config: Config, opts: { ask?: Ask; log?: (s: string) => void }): Promise<Set<Hit>> {
  const fallback = (v: string) => !/^(words|a UUID|\d+ digits)/.test(describe(v));
  if (!opts.ask || !config.jev) return new Set(generic.filter((g) => fallback(g.hit.value)).map((g) => g.hit));
  // One question per distinct value, asked about its first occurrence.
  const byValue = new Map<string, { seg: Segment; hit: Hit }>();
  for (const g of generic) if (!byValue.has(g.hit.value)) byValue.set(g.hit.value, g);
  const asked = [...byValue.values()];
  let verdict: Map<string, boolean>;
  try {
    const probs = await triage(
      opts.ask,
      asked.map(({ seg, hit }) => ({ context: contextOf(redacted(seg.buf, seg.hits), hit.start, hit.end), value: describe(hit.value) })),
    );
    verdict = new Map(asked.map((g, i) => [g.hit.value, probs[i] >= config.secretThreshold]));
  } catch (error) {
    opts.log?.(`Jev unavailable (${(error as Error).message}); keeping generic hits that look random`);
    verdict = new Map(asked.map((g) => [g.hit.value, fallback(g.hit.value)]));
  }
  return new Set(generic.filter((g) => verdict.get(g.hit.value)).map((g) => g.hit));
}

/**
 * Writes a masked segment back. Files: only the changed bytes, at their offsets, after checking
 * they still hold what was read, so a harness appending to (or holding open) the file is unaffected.
 * Rows: only if the row still holds what was read.
 */
function write(seg: Segment, masked: Buffer, dbs: Map<string, DatabaseSync>): boolean {
  const source = seg.source;
  if (source.kind === "rows") {
    const db = dbs.get(source.db) as DatabaseSync;
    const r = db.prepare(`UPDATE ${source.table} SET ${source.col} = ? WHERE rowid = ? AND ${source.col} = ?`).run(masked.toString("utf8"), seg.at, seg.buf.toString("utf8"));
    return r.changes > 0;
  }
  const fd = openSync(source.path, "r+");
  try {
    for (const h of seg.hits) {
      const current = Buffer.alloc(h.end - h.start);
      readSync(fd, current, 0, current.length, seg.at + h.start);
      if (!current.equals(seg.buf.subarray(h.start, h.end))) return false;
    }
    for (const h of seg.hits) writeSync(fd, masked, h.start, h.end - h.start, seg.at + h.start);
    return true;
  } finally {
    closeSync(fd);
  }
}
