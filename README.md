# agent-scrub

Lets a coding agent mask the credentials in its own session's chat log once it is done with
them. Claude Code, Codex, pi and opencode write every conversation to disk in plain text, so an
API key pasted into a chat, printed by `env` or read from `.env` stays there for good. The agent
knows when it no longer needs one; `agent-scrub done` is how it says so.

The agent learns to call it from the `scrub-credentials` skill (in
[dotfiles](https://github.com/justmytwospence/dotfiles), `dot_agents/skills/`), whose one-line
description is all a session pays for until a credential turns up.

## What `agent-scrub done` does

1. **Finds the calling session** from the environment each harness gives its commands:
   `CLAUDE_CODE_SESSION_ID`, `CODEX_THREAD_ID`, `OPENCODE=1` (opencode exports no id, so the
   most recently updated session for the working directory), `PI_SESSION_FILE`. They are
   checked in that order because a harness started from another's pane inherits its variables.
2. **Collects that session's text**, and only that session's:

   | Harness | Where |
   |---|---|
   | Claude Code | `~/.claude/projects/*/<id>.jsonl`, `<id>/` (subagents, saved tool results), its lines in `history.jsonl` |
   | Codex | `$CODEX_HOME/sessions/**/rollout-*-<id>.jsonl`, its rows in `thread_history_1.sqlite`, its lines in `history.jsonl` |
   | opencode | its `part`, `message` and `event` rows in `opencode.db` |
   | pi | the session file, and pi-cache-guard's saved tool output for it |

3. **Finds credentials** with [gitleaks](https://github.com/gitleaks/gitleaks)' rules (minus one
   that misfires on commit SHAs, `gitleaks.toml`) and an exact search for the credentials this
   machine holds: the values in `~/.config/dotfiles/secrets.env`, the tokens in the harnesses'
   auth files, and any `*_KEY`, `*_TOKEN`, `*_SECRET` or `*_PASSWORD` variable. A generic hit (a
   word like `token=` before a random-looking value) is kept only if Jev, given the surrounding
   text with the value replaced and a description of it ("40 random-looking characters"), says
   it is a credential. Jev never sees a value; without `TYPESAFE_API_KEY`, generic hits are kept
   unless they look like words, ids or numbers.
4. **Masks each one in place**: the bytes are overwritten with `*`, keeping a vendor prefix
   (`ghp_****`) and a private key's BEGIN and END lines. Files keep their size and every byte
   offset, so the harness, which is still writing the log (Codex keeps it open), is unaffected,
   and the byte offsets Codex stores in `thread_turns` stay valid. JSON escapes and quotes are
   left alone, so each line still parses. A byte range or row is only written if it still holds
   what was read.

It prints counts and rule names, never values. `--dry-run` reports without writing;
`--session <file | claude:<id> | codex:<id>>` names a session by hand.

What it does not do: change what the running agent already has in context (Claude Code, Codex
and pi keep the conversation in memory; a resumed or forked session sees the masks; opencode
re-reads its database every turn, so there the values are gone at once), or touch the
harnesses' own credential stores.

## Install

Needs Node 22.13+, 23.4+ or 24+ (type stripping and `node:sqlite`) and `gitleaks` on `PATH`; the
launcher adds Homebrew's prefixes, `~/.local/bin` and nvm's newest Node. Settings, all optional,
in `~/.config/agents/agent-scrub.json`:

```json
{
  "jev": true,
  "secretThreshold": 0.35,
  "secretsFiles": ["~/.config/dotfiles/secrets.env"],
  "authFiles": ["~/.codex/auth.json", "~/.pi/agent/auth.json"],
  "gitleaks": "gitleaks"
}
```

## Development

```sh
npm ci && npm run check
```
