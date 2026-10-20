<p align="center">
  <img src=".github/banner.jpg" alt="CakeAgent" style="max-width: 600px; width: 100%;">
</p>

# 🍰 CakeAgent

[![Build](https://github.com/kossov-it/cakeagent/actions/workflows/build.yml/badge.svg)](https://github.com/kossov-it/cakeagent/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

A personal AI agent you can actually read — around 5,300 lines of TypeScript across 12 source files and 3 runtime dependencies.

CakeAgent connects Claude to Telegram and gives it tools, voice, scheduling, file access, web fetch, and code execution. New capabilities come from two ecosystems: **MCP** (runtime tool servers) and **skills.sh** (knowledge-driven CLI integrations). Ask "add Google Calendar" in chat and it installs itself.

Runs as a single Node.js 22+ process under a dedicated system user. No containers, no web UI, no open ports.

---

## Why this exists

Open-source AI assistants have a bloat problem. The popular ones ship 400K+ lines of code, 50+ dependencies, WebSocket control planes, and custom plugin marketplaces — then get hit with critical RCE vulnerabilities and tens of thousands of exposed instances. Their plugin ecosystems? Some have been found to leak credentials.

CakeAgent does almost nothing itself and lets the ecosystem do the rest. The entire codebase is ~5,300 lines across 12 files. Integrations come from two open ecosystems — MCP (thousands of tool servers) and skills.sh (CLI knowledge packs). No custom plugin format, no marketplace.

| | CakeAgent | Popular alternatives |
|---|---|---|
| **Source code** | ~5,300 LOC, ~12 files | 400K+ LOC, 50+ modules |
| **Dependencies** | 3 | 47+ direct |
| **Open ports** | 0 | WebSocket, HTTP API |
| **Telegram** | ~400 LOC raw `fetch()` | Framework + adapter |
| **Integrations** | MCP + skills.sh | Custom plugin marketplace |
| **Security** | 9 hook groups + systemd watchdog + structured logging, ~125 deny patterns, every tool call audited | Varies — some have critical RCEs |
| **CVEs** | 0 | Multiple critical RCEs |

---

## Install

Linux server with Node.js 22+ required.

**Quick install:**

```bash
curl -fsSL https://raw.githubusercontent.com/kossov-it/cakeagent/main/install.sh | sudo bash
```

**Or manually:**

```bash
git clone https://github.com/kossov-it/cakeagent.git
cd cakeagent
sudo bash setup.sh
```

The setup script creates a `cakeagent` system user, installs everything to `/opt/cakeagent`, asks for your Telegram bot token and Claude credentials, and starts the service. Once running, send your bot a message — it walks you through the rest (name, personality, voice, integrations).

The setup script:

1. Checks Node.js
2. Creates a `cakeagent` system user (nologin shell, home at `/opt/cakeagent`)
3. Installs dependencies and builds
4. Configures passwordless sudo (`apt-get`, `apt`, `dpkg`, `systemctl`, `nft`, `iptables`, `ip6tables`, `ufw`, `firewall-cmd`, `fail2ban-client`, `netfilter-persistent`, `setup.sh`) — hooks restrict usage
5. Asks for your **Telegram bot token** — [get one from @BotFather](https://t.me/BotFather)
6. Asks for your **Telegram user ID** — [get it from @userinfobot](https://t.me/userinfobot)
7. Asks for **Claude authentication** (see below)
8. Installs and starts the systemd service

### Claude authentication

| Method | Where to get it | Saved as |
|--------|-----------------|----------|
| **Subscription token** (recommended) | Install [Claude Code CLI](https://www.npmjs.com/package/@anthropic-ai/claude-code), run `claude setup-token`, copy the `sk-ant-oat...` token (valid 1 year) | `CLAUDE_CODE_OAUTH_TOKEN` in `.env` |
| **API key** | [console.anthropic.com/settings/keys](https://console.anthropic.com/settings/keys), copy the `sk-ant-api...` key | `ANTHROPIC_API_KEY` in `.env` |

### Uninstall

```bash
sudo bash /opt/cakeagent/setup.sh uninstall
```

Removes the systemd service, the `cakeagent` user, the sudoers entry, and `/opt/cakeagent` entirely.

---

## Architecture

```
┌──────────────┐     ┌───────────────┐     ┌───────────────┐
│   Telegram   │────▶│  Orchestrator │────▶│  Claude Agent │
│  (raw fetch) │◀────│  (index.ts)   │◀────│  SDK query()  │
└──────────────┘     └───────┬───────┘     └──────┬────────┘
                             │                    │
       ┌─────────────────────┼────────────────────┤
       │                     │                    │
┌──────┴──────┐       ┌──────┴──────┐      ┌──────┴──────────┐
│   SQLite    │       │    Voice    │      │ Security Hooks  │
│ (store.ts)  │       │  STT / TTS  │      │  (5 PreToolUse  │
└─────────────┘       └─────────────┘      │  + SubagentStart│
                                           │   + PreCompact) │
                                           └──────┬──────────┘
       ┌──────────────────────────────────────────┴┐
       │              Tool Layer                   │
       │                                           │
       │  ┌─────────────┐ ┌───────────┐ ┌───────┐  │
       │  │  23 Built-in│ │ External  │ │Skills │  │
       │  │  MCP Tools  │ │ MCP (.mcp)│ │(.sh)  │  │
       │  └─────────────┘ └───────────┘ └───────┘  │
       └───────────────────────────────────────────┘
```

Messages go through three layers. Most never reach the Claude API:

1. **Settings callbacks** (inline keyboard buttons) — handled directly in the orchestrator
2. **Commands** (`/status`, `/settings`, `/update`, etc.) — handled in the orchestrator
3. **Everything else** — sent to Claude as a prompt with conversation context and persistent memory

---

## Features

### First run

On your first message, CakeAgent detects empty memory and starts an onboarding conversation — asks your name, language, personality, and suggests integrations. Everything is saved to `settings.json` and `memory.md`.

### Streaming

Responses are streamed as the agent works. Intermediate text (thinking, progress) appears immediately in Telegram instead of waiting for the full response.

### Memory and autonomous behavior

The agent has persistent memory in `data/memory.md`, injected into every prompt automatically. When you say "remember that..." or "from now on...", the agent writes to memory. Memory survives restarts and `/reset`.

Two system tasks run automatically (configurable via settings, disable by setting cron to empty string):

| Task | Default schedule | What it does |
|------|-----------------|-------------|
| **Morning check-in** | 8:57am daily | Reviews memory and scheduled tasks, sends a brief daily summary |
| **Dream** | 3:23am daily | Consolidates memory — removes outdated entries, merges duplicates, fixes contradictions |


Scheduling uses standard 5-field cron expressions (`minute hour day month weekday`). Missed tasks are recovered on restart — one-shot tasks fire, recurring tasks silently advance.

### Voice

Two separate toggles in `/settings` — **Voice In** (speech-to-text) and **Voice Out** (text-to-speech). Dependencies are installed automatically on first enable.

| | Provider | Runs where |
|---|---|---|
| **Speech-to-text** | whisper.cpp | Local (audio never leaves the server) |
| **Text-to-speech** | Edge TTS | Microsoft (free, no API key, no account) |

---

## Integrations

CakeAgent extends through two open ecosystems, searched **in parallel** when you ask to connect a service:

```
You:       "Connect to Google Calendar"
CakeAgent:  Found MCP server and a skill. MCP is preferred (structured tools).
            Install the MCP server?
You:       "Yes"
CakeAgent:  Installed. Available now.
```

**MCP servers** — The agent searches the [official MCP Registry](https://registry.modelcontextprotocol.io) for tool servers. Installed servers go into `.mcp.json`, load automatically on the next message, and get their own `/command` in the Telegram menu.

**Skills** — Knowledge packs from [skills.sh](https://skills.sh) inject documentation and CLI knowledge directly into the agent's prompt. Used when no MCP server exists for a service.

### Built-in tools

| Tool | What it does |
|------|-------------|
| `send_message` / `send_file` | Send progress updates or files mid-conversation |
| `schedule_task` / `list_schedules` / `update_schedule` / `delete_schedule` | Task scheduling with cron expressions (e.g. `0 9 * * 1-5` = weekdays at 9am) |
| `search_mcp_registry` | Search the official MCP registry |
| `web_fetch` | Fetch HTTPS pages/APIs with SSRF protection |
| `install_tool` / `remove_tool` / `list_tools` | Manage MCP servers |
| `install_skill` / `remove_skill` / `list_skills` / `read_skill` | Manage skills.sh integrations |
| `get_settings` / `update_settings` | Read or change settings (main only) |
| `register_group` / `list_groups` | Manage Telegram group chats (main only) |
| `update_memory` / `rewrite_memory` | Persistent memory across sessions |
| `search_messages` / `list_audit_events` | Full-text message search (FTS5) and security audit review |

---

## Security

CakeAgent gives Claude real system access — it installs packages, manages services, writes files, runs bash, and adds integrations. Five independent layers ensure this works without making the server a target.

| Layer | What it does |
|-------|-------------|
| **OS sandbox** | Dedicated `cakeagent` user (nologin shell), systemd `ProtectSystem=strict`, `ProtectHome=true`, `PrivateTmp=true`, `WatchdogSec=60` (Type=notify) |
| **Sudoers** | Passwordless sudo limited to `apt-get`, `apt`, `dpkg`, `systemctl`, `nft`, `iptables`, `ip6tables`, `ufw`, `firewall-cmd`, `fail2ban-client`, `netfilter-persistent`, and `setup.sh` only — destructive verbs still blocked by the bash hook |
| **PreToolUse hooks** | 9 hook groups validate every Bash, Read, Grep, Glob, Write, Edit, MultiEdit, NotebookEdit, and WebFetch call. ~125 Bash deny patterns cover shell injection, reverse shells, inline execution, destructive ops, secret access, critical system files, firewall mutations, source code writes, Unicode whitespace injection, control characters, IFS manipulation, process substitution, and zsh dangerous builtins. Commands are normalized (quotes/backslashes stripped, newlines folded) before pattern matching. |
| **Agent controls** | `acceptEdits` permission mode, `maxTurns: 25`, sender allowlist, rate limiting |
| **Runtime checks** | Prompt injection detection, memory/skill content sanitization, startup permission auto-fix (`.env`, `data/`, `.mcp.json`, `credentials/`) |
| **Structured logging** | JSON lines to stdout/stderr (`log.info/warn/error({fields}, message)`); `LOG_LEVEL` env var; secrets auto-redacted |

Additional hooks: **SubagentStart** logs all subagent launches to audit. **PreCompact** archives conversations on context compaction.

Every tool call is logged to the SQLite `audit_log` table. Injection attempts are logged with sender and content.

---

## Commands

| Command | What it does |
|---------|-------------|
| `/status` | Model, uptime, skills, active tasks, voice status |
| `/settings` | Inline keyboard — model (Haiku/Sonnet/Opus), thinking level, voice in/out, morning brief |
| `/skills` | List installed skills with source and install date |
| `/reset` | Clear conversation session (keeps memory and settings) |
| `/update` | Pull latest code, rebuild, restart |
| `/restart` | Restart without updating |
| `/help` | List commands |

```bash
sudo bash /opt/cakeagent/setup.sh update    # Same as /update
sudo journalctl -u cakeagent -f             # Live logs
sudo systemctl status cakeagent             # Service status
```

---

## Contributing

CakeAgent is intentionally small. Before adding a feature, ask: can the agent do this via an MCP server instead? If yes, don't add it to the codebase.

You can read the entire source in an hour. Please do before submitting a PR.
