// Settings and where things live.

import { existsSync, globSync, readFileSync } from "node:fs";
import { homedir } from "node:os";
import { join } from "node:path";

export interface Config {
  /** Ask Jev (needs TYPESAFE_API_KEY) whether a generic hit is a credential. */
  jev: boolean;
  /** Keep a generic hit (keyword plus a random-looking value) once Jev's probability that it is a credential reaches this. */
  secretThreshold: number;
  /** KEY=VALUE files whose values are masked wherever they appear. Glob patterns are expanded. */
  secretsFiles: string[];
  /**
   * Service env files (KEY=VALUE, glob patterns expanded): only values whose variable name
   * marks a credential (ending in KEY, TOKEN, SECRET, PASSWORD, PASS or CLIENT_ID) are masked,
   * so a DOMAIN or TZ in the same file is left alone.
   */
  envFiles: string[];
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
    envFiles: [],
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

/** A path with glob characters becomes the files it matches (sorted); a plain path stays as is. */
export function globbed(path: string): string[] {
  if (!/[*?[{]/.test(path)) return [path];
  return globSync(path, { withFileTypes: false }).sort();
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
    secretsFiles: (raw.secretsFiles ?? config.secretsFiles).map(expand).flatMap(globbed),
    envFiles: (raw.envFiles ?? config.envFiles).map(expand).flatMap(globbed),
    authFiles: (raw.authFiles ?? config.authFiles).map(expand),
  };
}
