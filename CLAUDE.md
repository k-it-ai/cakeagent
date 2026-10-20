# CakeAgent

## Purpose
Minimal, secure personal AI assistant built on the Claude Agent SDK. Connects to Telegram, runs agents via `query()`, manages integrations via MCP + skills.sh, supports voice.

## Tech Stack
- **Runtime**: Node.js 22+ (ESM)
- **Agent**: `@anthropic-ai/claude-agent-sdk` — `query()`, `createSdkMcpServer`, `tool()`, hooks
- **Storage**: `better-sqlite3` (SQLite with WAL mode)
- **Validation**: `zod` (v4, peer dep of Agent SDK)
- **Telegram**: Raw `fetch()` — no framework, 0 deps
- **Voice (optional)**: `edge-tts` for TTS, local `whisper-cli` for STT — no API keys
- **Security**: `src/security.ts` (URL/IP validation), `src/scheduler.ts` (schedule advancement)

## Directory Layout
```
src/index.ts        — Orchestrator: poll loop, routing, debounce, cron scheduler, memory extraction, .env loading, system tasks, shutdown
src/agent.ts        — Agent SDK wrapper: query(), session resume, streaming
src/tools.ts        — In-process MCP server: 23 tools (schedule/skills/MCP/memory/search/audit/web_fetch)
src/cron.ts         — 5-field cron parser + @nicknames + cronToHuman()
src/hooks.ts        — Security hooks: 9 PreToolUse matcher groups + SubagentStart + PreCompact; Bash disabled in groups
src/store.ts        — SQLite CRUD (messages, schedules, groups, sessions, audit, skills); monotonic message_seq
src/voice.ts        — STT (whisper-cli) + TTS (edge-tts); temp files O_NOFOLLOW
src/types.ts        — Shared types + validation constants
src/security.ts     — URL/IP validation, canonicalPath, safeFetch helpers
src/scheduler.ts    — Extracted advanceScheduledTask for recurring/interval/cron
channels/telegram.ts — Raw fetch Telegram adapter (retry, HTML, chunking)
groups/main/CLAUDE.md — Agent identity + rules (not this file)
data/skills/        — Installed skill content (.md) + index.json
```

## Build / Run / Test
```bash
npm install          # Install dependencies
npm run dev          # Development (tsx) — .env must be readable by service user
npm run build        # Compile TypeScript
npm start            # Production (node dist/)
npx tsc --noEmit     # Type-check only
npm test             # Run test suite (tsx)
```

## Key Conventions
- ESM only (`"type": "module"`) — use `.js` extensions in imports
- No framework dependencies for HTTP — raw `fetch()` everywhere
- In-process MCP server via `createSdkMcpServer` — no child process IPC
- Two integration paths: MCP servers (runtime tools) and skills.sh (CLI-based, knowledge-driven)
- Skills stored in `data/skills/`, loaded into prompt as `[SKILLS]` block (lazy summaries, `read_skill` on demand)
- `acceptEdits` permission mode — never `bypassPermissions`
- CLAUDE.md in `groups/*/` is read-only for the agent — memory goes to `data/memory.md`
- Group chats do not have Bash or Agent subagent access (hooks + SDK allowlist)
- Sequential processing — one agent invocation at a time
- Settings hot-reloaded from `data/settings.json` per invocation
- Cron scheduling via `src/cron.ts` — 5-field cron expressions
- System tasks (morning check-in, dream) created on first boot via `ensureSystemTasks()` in index.ts; prompts updated on code change
- Auto memory extraction runs every N conversations — silent background agent call (memory tools only)
- Missed scheduled tasks recovered on startup (one-shot fire, recurring advance); invalid cron pauses
- Task queue prevents dropped tasks when agent is busy

## Security
- Dedicated `cakeagent` system user with nologin shell
- systemd: `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `ProtectKernelTunables`, `ProtectKernelModules`, `ProtectControlGroups`, `ProtectClock`, `ProtectHostname`, `ProtectProc=invisible`, `LockPersonality`, `RestrictRealtime`, `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX AF_NETLINK`, `CapabilityBoundingSet=0`
- **Watchdog**: `Type=notify` with `WatchdogSec=60` — agent sends `READY=1` at startup and `WATCHDOG=1` every 30s via `sd_notify`; systemd restarts if ping missed
- **Structured logging**: JSON lines to stdout/stderr via `src/logger.ts` (`log.info/warn/error({fields}, 'message')`); set `LOG_LEVEL=debug|info|warn|error` (default: info); secrets auto-redacted
- **Design tradeoff**: `ReadWritePaths=/opt/cakeagent /usr /var /etc` is broad (defeats `ProtectSystem=strict` partially) to allow `install-config` to write systemd/nginx/etc configs. Narrowing would break the helper's purpose. Documented residual risk: a compromised main agent could write to any of these trees via `sudo install-config`. Mitigated by: helper validates target paths, rejects critical files, and sources restricted to `data/tmp/`.
- Sudoers whitelist: `apt-get`, `apt`, `dpkg`, `systemctl`, `nft`, `iptables`, `ip6tables`, `ufw`, `firewall-cmd`, `fail2ban-client`, `netfilter-persistent`, and helper subcommands `install-config`, `remove-config`, `certbot`, `harden-sshd`
- `setup.sh install-config <path>` writes validated config files to allowlisted `/etc/` prefixes (nginx, apache2, caddy, systemd units/timers/sockets, sysctl.d, apt sources/prefs/keyrings, prometheus, grafana, alertmanager, logrotate, fail2ban, ufw apps, nftables, certbot cli.ini, letsencrypt hooks). Critical files (sudoers, shadow, ssh, pam.d, cron.d, ld.so.preload, hosts, resolv.conf, fstab, cakeagent.service, sysctl.conf) hard-denied in helper *and* Bash/Write hooks. Sources restricted to `data/tmp/` or private `/tmp/` (no settings/memory/db leaks). Resolved target revalidated after parent mkdir to catch symlinked-parent swaps.
- `setup.sh certbot <args>` — wraps certbot, strips hook flags (`--pre-hook`, `--deploy-hook`, etc.) and path-redirection flags (`--config`, `--config-dir`, `--work-dir`, `--logs-dir`, `--cert-path`, `--key-path`, `--nginx-*`, `--apache-*`) that would allow RCE-as-root via sudoers. Renewal hooks go to `/etc/letsencrypt/renewal-hooks/{pre,deploy,post}/` via install-config instead.
- `setup.sh harden-sshd` — installs fixed known-safe `/etc/ssh/sshd_config.d/99-cakeagent-hardening.conf` (no user input — prevents foot-gun directives), validates via `sshd -t`, reverts on failure, reloads sshd. Arbitrary sshd_config writes never allowed. **Checks for existing `authorized_keys` before disabling password auth to prevent lockout.**
- Podman (rootless) is the container runtime, not Docker — the agent never joins the `docker` group (root-equivalent) and never runs a privileged daemon.
- `systemctl reload ssh` allowed — ssh.service ExecReload runs `sshd -t` before HUP. `stop`/`restart`/`disable`/`enable`/`mask` on ssh/sshd/networking blocked. `systemctl * ssh.socket` also blocked.
- 9 PreToolUse matcher groups + SubagentStart + PreCompact:
  - Global allowlist for constrained runs (memory extraction, system tasks)
  - Bash: main chat only; groups get **no Bash at all** (hooks + SDK allowlist). Main: ~125 deny patterns covering shell injection, sensitive reads, destructive writes, systemctl/networking abuse, firewall tampering, `/proc`/`/dev` secrets, Unicode/control-char bypasses. Commands normalized (quotes/backslashes removed, newlines folded).
  - Read: sensitive paths + cross-group escape + data-root (except downloads/tmp)
  - Grep/Glob: search root restricted to group folder + `data/downloads/<group>` + `data/tmp`; sensitive glob patterns + unsafe globs (`..`, `~`, `$`, absolute) blocked
  - Write/Edit/MultiEdit/NotebookEdit: protected paths + cross-group escape
  - WebFetch (built-in): URL validated via `isSafeOutboundUrl` (defense-in-depth; not in SDK allowlist)
- Symlink-aware path checks via `canonicalPath` (realpath nearest existing ancestor) in hooks and store
- SSRF guard on outbound fetch (`safeFetch`): manual redirect following, DNS resolution on every hop, rejects private/loopback/link-local/CGNAT/multicast/reserved IPv4 and IPv6 (ULA, link-local, 6to4, Teredo, NAT64)
- Outbound file validation: `send_file` only from group folder, `data/downloads/<group>`, or `data/tmp`; revalidated immediately before upload (catches parent symlink swap)
- SubagentStart hook logs all subagent launches to audit_log
- PreCompact hook archives conversations on context compaction; signals memory extraction from messages about to be lost
- Bash commands normalized (quotes/backslashes removed, newlines folded) before deny-pattern matching
- Settings validated: model, thinkingLevel, voiceTtsVoice checked against allowed values
- Skill content capped at 50 KB, memory.md capped at 50 KB
- Atomic writes for settings.json, skills/index.json, memory.md, config files (unpredictable `wx` temp, `rename`)
- Prompt injection detection: flagged messages get security warning prepended
- Memory/skill content sanitized via `sanitizeMemory()` before storage (strips credential/injection lines)
- Rate limiting persisted in SQLite; all tool calls logged to audit_log (secrets redacted)
- Chat ID + sender allowlist — only configured Telegram chats and senders processed
- Concurrency guard (`agentBusy`) — one agent invocation at a time
- `.env` permission check on startup (warns if not 600; root-owned file read by systemd, agent falls back to process.env)
- `unhandledRejection` handler with audit logging (secrets redacted)
- Message cursors stored in SQLite `message_seq` (AUTOINCREMENT) and KV (`chat_cursor:<chatId>`); `rowid` backfill on upgrade; survives pruning
- Group isolation: groups cannot read/write other groups' folders, cannot list groups, cannot change global settings/install tools/skills/register groups, cannot Bash, cannot subagent
- MCP external servers: `.mcp.json` symlink refused; dangerous env (`LD_PRELOAD`, `NODE_OPTIONS`, etc.) and args (`-e`, `-c`, `--privileged`, `-v`, `--mount`, `--env-file`) blocked; registry metadata marked untrusted
