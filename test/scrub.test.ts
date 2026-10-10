import { closeSync, mkdirSync, mkdtempSync, openSync, readFileSync, rmSync, writeFileSync, writeSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { DatabaseSync } from "node:sqlite";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { loadConfig } from "../src/config.ts";
import type { Ask } from "../src/jev.ts";
import { scrub } from "../src/scrub.ts";
import { callingSession } from "../src/session.ts";

// Tokens are generated so that nothing credential-shaped is committed.
const ALNUM = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789";
const random = (n: number) => Array.from({ length: n }, () => ALNUM[Math.floor(Math.random() * ALNUM.length)]).join("");
const githubToken = () => `ghp_${random(36)}`;
const line = (text: string, extra: Record<string, string> = {}) => `${JSON.stringify({ ...extra, message: { role: "user", content: text } })}\n`;

let home: string;
beforeEach(() => {
  home = mkdtempSync(join(tmpdir(), "agent-scrub-"));
  process.env.AGENT_SCRUB_HOME = home;
});
afterEach(() => {
  rmSync(home, { recursive: true, force: true });
  delete process.env.AGENT_SCRUB_HOME;
});
const config = () => ({ ...loadConfig(), secretsFiles: [join(home, "secrets.env")], authFiles: [] });

describe("callingSession", () => {
  it("prefers the harness's own variable over one inherited from pi", () => {
    const env = { PI_SESSION_FILE: "/x/pi.jsonl", CLAUDE_CODE_SESSION_ID: "abc" };
    expect(callingSession(env)?.harness).toBe("claude");
    expect(callingSession({ PI_SESSION_FILE: "/x/pi.jsonl", CODEX_THREAD_ID: "t" })?.harness).toBe("codex");
    expect(callingSession({ PI_SESSION_FILE: "/x/pi.jsonl" })?.harness).toBe("pi");
    expect(callingSession({})).toBeUndefined();
  });
});

describe("scrub", () => {
  it("masks a Claude Code session, its subagents and its own history lines only", async () => {
    const id = "11111111-2222-3333-4444-555555555555";
    const dir = join(home, ".claude", "projects", "-p");
    mkdirSync(join(dir, id, "subagents"), { recursive: true });
    const token = githubToken();
    const other = githubToken();
    writeFileSync(join(dir, `${id}.jsonl`), line(`use ${token}`) + line("ok"));
    writeFileSync(join(dir, id, "subagents", "a.jsonl"), line(`sub ${token}`));
    writeFileSync(join(dir, "other.jsonl"), line(`not mine ${other}`));
    const history = join(home, ".claude", "history.jsonl");
    writeFileSync(history, line(`paste ${token}`, { sessionId: id }) + line(`paste ${other}`, { sessionId: "someone-else" }));
    const before = readFileSync(join(dir, `${id}.jsonl`)).length;

    const dry = await scrub(callingSession({ CLAUDE_CODE_SESSION_ID: id })!, config(), { dryRun: true });
    expect(dry.masked).toBe(3);
    expect(readFileSync(join(dir, `${id}.jsonl`), "utf8")).toContain(token);

    const r = await scrub(callingSession({ CLAUDE_CODE_SESSION_ID: id })!, config());
    expect(r.masked).toBe(3);
    const transcript = readFileSync(join(dir, `${id}.jsonl`), "utf8");
    expect(transcript).not.toContain(token);
    expect(transcript).toContain("ghp_****");
    expect(transcript.length).toBe(before);
    for (const l of transcript.trim().split("\n")) expect(() => JSON.parse(l)).not.toThrow();
    expect(readFileSync(join(dir, id, "subagents", "a.jsonl"), "utf8")).not.toContain(token);
    const h = readFileSync(history, "utf8");
    expect(h).not.toContain(token);
    expect(h).toContain(other);
    expect(readFileSync(join(dir, "other.jsonl"), "utf8")).toContain(other);
  });

  it("masks a Codex rollout the harness holds open, and its thread_history rows", async () => {
    const id = "0199aaaa-bbbb-cccc-dddd-eeeeeeeeeeee";
    const dir = join(home, ".codex", "sessions", "2026", "01", "01");
    mkdirSync(dir, { recursive: true });
    const rollout = join(dir, `rollout-2026-01-01T00-00-00-${id}.jsonl`);
    const token = githubToken();
    const fd = openSync(rollout, "a");
    writeSync(fd, line(`token ${token}`));
    const db = new DatabaseSync(join(home, ".codex", "thread_history_1.sqlite"));
    db.exec("CREATE TABLE thread_items (thread_id TEXT, turn_id TEXT, item_id TEXT, item_json TEXT)");
    db.prepare("INSERT INTO thread_items VALUES (?, 't', 'i', ?)").run(id, JSON.stringify({ text: token }));
    const r = await scrub(callingSession({ CODEX_THREAD_ID: id })!, config());
    expect(r.masked).toBe(2);
    writeSync(fd, line("appended after the mask"));
    closeSync(fd);
    const lines = readFileSync(rollout, "utf8").trim().split("\n");
    expect(lines[0]).not.toContain(token);
    expect(JSON.parse(lines[1]).message.content).toBe("appended after the mask");
    expect((db.prepare("SELECT item_json AS j FROM thread_items").get() as { j: string }).j).not.toContain(token);
    db.close();
  });

  it("masks the newest opencode session for this directory", async () => {
    const dir = join(home, ".local", "share", "opencode");
    mkdirSync(dir, { recursive: true });
    const db = new DatabaseSync(join(dir, "opencode.db"));
    db.exec("CREATE TABLE session (id TEXT, directory TEXT, time_updated INTEGER)");
    db.exec("CREATE TABLE part (id TEXT, session_id TEXT, data TEXT)");
    db.exec("INSERT INTO session VALUES ('ses_old', '/w', 1), ('ses_new', '/w', 2), ('ses_elsewhere', '/x', 3)");
    const mine = githubToken();
    const theirs = githubToken();
    db.prepare("INSERT INTO part VALUES ('p1', 'ses_new', ?), ('p2', 'ses_elsewhere', ?)").run(JSON.stringify({ text: mine }), JSON.stringify({ text: theirs }));
    const session = callingSession({ OPENCODE: "1", PI_SESSION_FILE: "/inherited" }, "/w")!;
    expect(session.id).toBe("ses_new");
    await scrub(session, config());
    const rows = db.prepare("SELECT data FROM part ORDER BY id").all() as { data: string }[];
    db.close();
    expect(rows[0].data).not.toContain(mine);
    expect(rows[1].data).toContain(theirs);
  });

  it("masks known values in a pi session and its saved tool output", async () => {
    const id = "01a12690-5b9f-70a1-8762-b6104823357e";
    const file = join(home, ".pi", "agent", "sessions", "--w--", `2026-01-01T00-00-00-000Z_${id}.jsonl`);
    const out = join(home, ".pi", "agent", "cache-guard", "tool-output", id);
    mkdirSync(join(file, ".."), { recursive: true });
    mkdirSync(out, { recursive: true });
    const key = `ts_${random(40)}`;
    writeFileSync(join(home, "secrets.env"), `TEST_SERVICE_KEY=${key}\n`);
    writeFileSync(file, line(`export TEST_SERVICE_KEY=${key}`));
    writeFileSync(join(out, "toolu_1.txt"), `TEST_SERVICE_KEY=${key}\n`);
    const r = await scrub(callingSession({ PI_SESSION_FILE: file, PI_SESSION_ID: id })!, config());
    expect(r.rules.get("known:TEST_SERVICE_KEY")).toBe(2);
    expect(readFileSync(file, "utf8")).not.toContain(key);
    expect(readFileSync(join(out, "toolu_1.txt"), "utf8")).not.toContain(key);
  });

  it("keeps a generic hit only when Jev calls it a credential, without showing Jev the value", async () => {
    const file = join(home, ".pi", "agent", "sessions", "s.jsonl");
    mkdirSync(join(file, ".."), { recursive: true });
    const key = random(40);
    writeFileSync(file, line(`OUTLINE_API_KEY=${key}\nkey_account="brand_key_account_name"`));
    const sent: string[] = [];
    const ask: Ask = async (state, questions) => {
      sent.push(JSON.stringify(state));
      const s = state as Record<string, { value: string }>;
      return Object.fromEntries(Object.keys(questions).map((id) => [id, /random/.test(s[id]?.value ?? "") ? 0.9 : 0.05]));
    };
    await scrub(callingSession({ PI_SESSION_FILE: file })!, config(), { ask });
    const text = readFileSync(file, "utf8");
    expect(text).not.toContain(key);
    expect(text).toContain("brand_key_account_name");
    expect(sent.join("")).not.toContain(key);
  });
});
