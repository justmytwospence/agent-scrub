// agent-scrub: an agent masks the credentials in its own session's chat log once it is done with
// them (the scrub-credentials skill). Never prints a value.

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { type Config, loadConfig } from "../src/config.ts";
import { jevClient } from "../src/jev.ts";
import { scrub } from "../src/scrub.ts";
import { callingSession, claudeSession, codexSession, piSession, type Session } from "../src/session.ts";

const USAGE = `agent-scrub: mask credentials in a coding agent's chat log

  agent-scrub done [--dry-run]
      Run by the agent (scrub-credentials skill) when it no longer needs the credentials in its
      conversation: masks them in this session's log (Claude Code, Codex, opencode or pi, found
      from the environment), in place. --dry-run only reports.
  agent-scrub done --session <file | claude:<id> | codex:<id>> [--dry-run]
      The same for a session named by hand.

Prints counts and rule names, never values. Settings: ~/.config/agents/agent-scrub.json.`;

function jevKey(config: Config): string | undefined {
  const env = process.env.TYPESAFE_API_KEY?.trim();
  if (env) return env;
  for (const file of config.secretsFiles) {
    if (!existsSync(file)) continue;
    const m = /^\s*(?:export\s+)?TYPESAFE_API_KEY\s*=\s*['"]?([^'"\s]+)/m.exec(readFileSync(file, "utf8"));
    if (m) return m[1];
  }
  return undefined;
}

function named(spec: string): Session {
  if (spec.startsWith("claude:")) return claudeSession(spec.slice(7));
  if (spec.startsWith("codex:")) return codexSession(spec.slice(6));
  if (!existsSync(spec)) throw new Error(`no such session file: ${spec}`);
  if (spec.includes("/.pi/")) return piSession(spec);
  return { harness: "file", id: spec, sources: [{ kind: "file", path: spec }] };
}

const tilde = (p: string) => (p.startsWith(homedir()) ? `~${p.slice(homedir().length)}` : p);

async function main(): Promise<void> {
  const args = process.argv.slice(2);
  const [command] = args;
  if (command !== "done") {
    console.log(USAGE);
    if (command && !["help", "--help", "-h"].includes(command)) process.exitCode = 2;
    return;
  }
  const dryRun = args.includes("--dry-run");
  const i = args.indexOf("--session");
  const config = loadConfig();
  const session = i >= 0 ? named(args[i + 1] ?? "") : callingSession();
  if (!session) throw new Error("not run by Claude Code, Codex, opencode or pi (no session in the environment); pass --session");
  if (session.sources.length === 0) throw new Error(`found no log for ${session.harness} session ${session.id}`);
  const log = (line: string) => process.stderr.write(`agent-scrub: ${line}\n`);
  const result = await scrub(session, config, { dryRun, ask: config.jev ? jevClient(jevKey(config)) : undefined, log });
  const verb = dryRun ? "would mask" : "masked";
  if (result.masked === 0) {
    console.log(`no credentials in ${session.harness} session ${session.id}`);
    return;
  }
  const rules = [...result.rules].map(([r, n]) => `${r} x${n}`).join(", ");
  console.log(`${verb} ${result.masked} in ${session.harness} session ${session.id}: ${rules}`);
  for (const where of result.changed) console.log(`  ${tilde(where)}`);
}

main().catch((error) => {
  process.stderr.write(`agent-scrub: ${error instanceof Error ? error.message : String(error)}\n`);
  process.exitCode = 1;
});
