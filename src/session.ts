// Which session called us, and where that session's log lives. Each harness puts its session id
// in the environment of the commands it runs; opencode only sets OPENCODE=1, so its session is the
// most recently updated one for this directory. The checks run in this order because a harness
// started from another's pane inherits its variables (opencode under pi sees PI_SESSION_FILE).

import { existsSync, lstatSync, readdirSync } from "node:fs";
import { basename, join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { codexHome, home } from "./config.ts";

/** Where a session's text lives: a whole file, the lines of a shared file that mention the session, or table rows. */
export type Source =
  | { kind: "file"; path: string; lines?: string }
  | { kind: "rows"; db: string; table: string; col: string; key: string; value: string };

export interface Session {
  harness: "claude" | "codex" | "opencode" | "pi" | "file";
  id: string;
  sources: Source[];
}

function* walk(path: string): Generator<string> {
  let st;
  try {
    st = lstatSync(path);
  } catch {
    return;
  }
  if (st.isSymbolicLink()) return;
  if (st.isFile()) yield path;
  else if (st.isDirectory()) for (const name of readdirSync(path)) yield* walk(join(path, name));
}

const files = (paths: string[]): Source[] => paths.filter((p) => existsSync(p)).map((path) => ({ kind: "file", path }));
const historyLines = (path: string, id: string): Source[] => (existsSync(path) ? [{ kind: "file", path, lines: id }] : []);

export function claudeSession(id: string): Session {
  const projects = join(home(), ".claude", "projects");
  const paths: string[] = [];
  for (const project of existsSync(projects) ? readdirSync(projects) : []) {
    const transcript = join(projects, project, `${id}.jsonl`);
    if (existsSync(transcript)) paths.push(transcript);
    paths.push(...walk(join(projects, project, id))); // subagents and saved tool results
  }
  return { harness: "claude", id, sources: [...files(paths), ...historyLines(join(home(), ".claude", "history.jsonl"), id)] };
}

export function codexSession(id: string): Session {
  const rollouts = [...walk(join(codexHome(), "sessions"))].filter((p) => p.endsWith(`${id}.jsonl`));
  const db = join(codexHome(), "thread_history_1.sqlite");
  const rows: Source[] = existsSync(db)
    ? [
        { kind: "rows", db, table: "thread_items", col: "item_json", key: "thread_id", value: id },
        { kind: "rows", db, table: "thread_realtime_items", col: "item_json", key: "thread_id", value: id },
      ]
    : [];
  return { harness: "codex", id, sources: [...files(rollouts), ...rows, ...historyLines(join(codexHome(), "history.jsonl"), id)] };
}

export function opencodeSession(cwd: string): Session | undefined {
  const db = join(home(), ".local", "share", "opencode", "opencode.db");
  if (!existsSync(db)) return undefined;
  const conn = new DatabaseSync(db); // read-only handles fail on a WAL database whose -shm is missing
  try {
    const row = (conn.prepare("SELECT id FROM session WHERE directory = ? ORDER BY time_updated DESC LIMIT 1").get(cwd) ??
      conn.prepare("SELECT id FROM session ORDER BY time_updated DESC LIMIT 1").get()) as { id: string } | undefined;
    if (!row) return undefined;
    const id = row.id;
    return {
      harness: "opencode",
      id,
      sources: [
        { kind: "rows", db, table: "part", col: "data", key: "session_id", value: id },
        { kind: "rows", db, table: "message", col: "data", key: "session_id", value: id },
        { kind: "rows", db, table: "event", col: "data", key: "aggregate_id", value: id },
      ],
    };
  } finally {
    conn.close();
  }
}

export function piSession(file: string, id?: string): Session {
  const sessionId = id ?? /_([0-9a-f-]{36})\.jsonl$/.exec(basename(file))?.[1] ?? basename(file);
  const toolOutput = join(home(), ".pi", "agent", "cache-guard", "tool-output", sessionId);
  return { harness: "pi", id: sessionId, sources: files([file, ...walk(toolOutput)]) };
}

/** The session whose agent ran this command, from the harness's environment. */
export function callingSession(env: NodeJS.ProcessEnv = process.env, cwd = process.cwd()): Session | undefined {
  if (env.CLAUDE_CODE_SESSION_ID) return claudeSession(env.CLAUDE_CODE_SESSION_ID);
  if (env.CODEX_THREAD_ID) return codexSession(env.CODEX_THREAD_ID);
  if (env.OPENCODE === "1") return opencodeSession(cwd);
  if (env.PI_SESSION_FILE) return piSession(env.PI_SESSION_FILE, env.PI_SESSION_ID);
  return undefined;
}
