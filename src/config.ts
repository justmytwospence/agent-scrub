// Settings and where things live.

import { existsSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface Config {
  /** Ask Jev (needs TYPESAFE_API_KEY) whether a generic hit is a credential. */
  jev: boolean;
  /** Keep a generic hit (keyword plus a random-looking value) once Jev's probability that it is a credential reaches this. */
  secretThreshold: number;
  /** KEY=VALUE files whose values are masked wherever they appear. */
  secretsFiles: string[];
  /** JSON files whose credential values (keys ending in token, key, secret, password) are masked wherever they appear. */
  authFiles: string[];
  /** The gitleaks binary. */
  gitleaks: string;
}

export function home(): string {
  return process.env.AGENT_SCRUB_HOME ?? homedir();
}

export function codexHome(): string {
  return process.env.CODEX_HOME ?? join(home(), ".codex");
}

export function configPath(): string {
  return join(home(), ".config", "agents", "agent-scrub.json");
}

export function defaults(): Config {
  const h = home();
  return {
    jev: true,
    secretThreshold: 0.35,
    secretsFiles: [join(h, ".config", "dotfiles", "secrets.env")],
    authFiles: [
      join(codexHome(), "auth.json"),
      join(h, ".claude", ".credentials.json"),
      join(h, ".pi", "agent", "auth.json"),
      join(h, ".pi", "agent", "mcp-auth.json"),
      join(h, ".local", "share", "opencode", "auth.json"),
      join(h, ".local", "share", "opencode", "mcp-auth.json"),
    ],
    gitleaks: "gitleaks",
  };
}

export function loadConfig(): Config {
  const config = defaults();
  const path = configPath();
  if (!existsSync(path)) return config;
  const raw = JSON.parse(readFileSync(path, "utf8")) as Partial<Config>;
  for (const key of Object.keys(raw)) {
    if (!(key in config)) throw new Error(`${path}: unknown setting \`${key}\``);
  }
  const expand = (p: string) => (p.startsWith("~/") ? join(home(), p.slice(2)) : p);
  return {
    ...config,
    ...raw,
    secretsFiles: (raw.secretsFiles ?? config.secretsFiles).map(expand),
    authFiles: (raw.authFiles ?? config.authFiles).map(expand),
  };
}
