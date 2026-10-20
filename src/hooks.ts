import type { HookInput } from '@anthropic-ai/claude-agent-sdk';
import type { RunState } from './types.js';
import { logAudit, getMessagesSince } from './store.js';
import { isSafeOutboundUrl, canonicalPath, isPathInside } from './security.js';
import { mkdirSync, writeFileSync } from 'node:fs';
import { homedir } from 'node:os';
import { join, resolve, isAbsolute } from 'node:path';

// Normalize command for pattern matching. Quotes and backslashes are removed
// (to defeat `b"a"sh`), and newlines are folded to spaces (to defeat
// `cat\n.env` / backslash-newline continuations).
export function normalizeCommand(cmd: string): string {
  return cmd.replace(/["'\\]/g, '').replace(/[\r\n]+/g, ' ').replace(/[ \t]+/g, ' ').trim();
}

const PROJECT_ROOT = resolve(process.cwd());
const ESCAPED_ROOT = PROJECT_ROOT.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
const DEFAULT_DATA_DIR = resolve(process.env.DATA_DIR || join(PROJECT_ROOT, 'data'));
const HELPER_DIR = '/usr/local/lib/cakeagent';

function escapeRegExp(value: string): string {
  return value.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// The agent's cwd is normally groups/<folder>, so relative paths are resolved
// there. Absolute paths (and traversal such as ../../src) still need to be
// checked against the installation tree.
const SELF_PROTECTED_PATHS = [
  new RegExp(`^${ESCAPED_ROOT}$`),
  new RegExp(`^${ESCAPED_ROOT}/(?:src|channels|dist)(?:/|$)`),
  new RegExp(`^${ESCAPED_ROOT}/(?:package\\.json|package-lock\\.json|tsconfig\\.json|cakeagent\\.service|setup\\.sh|CLAUDE\\.md)$`),
  new RegExp(`^${escapeRegExp(HELPER_DIR)}(?:/|$)`),
];

/** Split a normalized command into path-like tokens (redirections included). */
function bashTokens(cmd: string): string[] {
  const tokens: string[] = [];
  const re = /(?:^|[\s=<>|;&])([^\s;|&<>]+)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(cmd)) !== null) {
    let token = match[1]!;
    // `--file=/path`, `curl @file`, and similar forms still name a path.
    const eq = token.indexOf('=');
    if (eq >= 0) token = token.slice(eq + 1);
    if (token.startsWith('@')) token = token.slice(1);
    if (token) tokens.push(token);
  }
  return tokens;
}

function tokenCandidates(token: string, baseDir: string, extraDirs: string[] = []): string[] {
  if (!token || token.startsWith('/dev/')) return [];
  // Support options with an attached path (`-o/etc/passwd`, `-I/usr`), which
  // otherwise look like flags and bypass the path check.
  const attachedPath = token.match(/^-[A-Za-z]+(\/.*)$/);
  if (attachedPath) token = attachedPath[1]!;
  else if (token.startsWith('-')) return [];
  // Expand the two shell variables whose values we actually know. Other
  // variables are left unresolved rather than guessed; the static hook cannot
  // be a sandbox for arbitrary interpreter code (see README security notes).
  if (token === '$HOME' || token === '${HOME}') token = homedir();
  else if (token.startsWith('$HOME/')) token = homedir() + token.slice(5);
  else if (token.startsWith('${HOME}/')) token = homedir() + token.slice(7);
  else if (token === '$PWD' || token === '${PWD}') token = baseDir;
  else if (token.startsWith('$PWD/')) token = baseDir + token.slice(4);
  else if (token.startsWith('${PWD}/')) token = baseDir + token.slice(6);

  const candidates: string[] = [];
  const add = (absolute: string) => {
    candidates.push(absolute, canonicalPath(absolute));
  };

  if (isAbsolute(token)) add(resolve(token));
  else if (token.startsWith('~/')) add(resolve(homedir(), token.slice(2)));
  else if (token.startsWith('~')) return [];
  else {
    add(resolve(baseDir, token));
    // A `cd dir && ...` chain changes how later relative paths resolve. The
    // Claude Code shell can also carry cwd within the project; we disable that
    // below with CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR, but still check the
    // command's explicit cd targets here.
    for (const dir of extraDirs) add(resolve(dir, token));
  }
  return candidates;
}

function bashCdTargets(cmd: string, baseDir: string): string[] {
  const targets: string[] = [];
  const re = /(?:^|[;&|]\s*)\s*(?:cd|pushd)\s+([^\s;|&]+)/g;
  let match: RegExpExecArray | null;
  while ((match = re.exec(cmd)) !== null) {
    const token = match[1]!;
    const candidates = tokenCandidates(token, baseDir);
    if (candidates[0]) targets.push(candidates[0]);
  }
  return targets;
}

const TRUSTED_HELPER = join(HELPER_DIR, 'setup.sh');
const TRUSTED_HELPER_RE = new RegExp(
  `(?:^|[|;&]\\s*)\\s*sudo\\s+(?:-n\\s+)?bash\\s+(${escapeRegExp(TRUSTED_HELPER)})\\s+` +
  `(?:install-config|remove-config|certbot|harden-sshd)(?:\\s|$)`,
);

function trustedHelperPath(cmd: string): string | null {
  return TRUSTED_HELPER_RE.exec(cmd)?.[1] ?? null;
}

function isSamePathToken(token: string, expected: string, baseDir: string): boolean {
  return tokenCandidates(token, baseDir).some(c => c === expected);
}

/** Find a path under this installation's protected source tree in a Bash command. */
export function findBashSelfWrite(cmd: string, baseDir = join(PROJECT_ROOT, 'groups', 'main')): RegExp | null {
  const normalized = normalizeCommand(cmd);
  const helper = trustedHelperPath(normalized);
  let skippedHelper = false;
  const cdTargets = bashCdTargets(normalized, baseDir);
  for (const token of bashTokens(normalized)) {
    if (helper && !skippedHelper && isSamePathToken(token, helper, baseDir)) {
      skippedHelper = true;
      continue;
    }
    // A shell glob can expand into protected children even though the literal
    // path (`/opt/cakeagent/*`) is not itself in the deny list.
    const globAt = token.search(/[*?[]/);
    const tokenToCheck = globAt >= 0 ? token.slice(0, globAt) : token;
    const candidates = tokenCandidates(tokenToCheck, baseDir, cdTargets);
    const hit = SELF_PROTECTED_PATHS.find(p => candidates.some(c => p.test(c)));
    if (hit) return hit;
  }
  return null;
}

function commandWrites(cmd: string): boolean {
  return /(>>?|\bsed\s+-i\b|\b(tee|cp|mv|rm|rmdir|mkdir|touch|chmod|chown|ln|truncate|install|dd|patch|rsync|unlink)\b|\bgit\s+(?:apply|checkout|restore|clean|reset|stash|switch)\b|\b(?:curl|wget)\b.*(?:\s-[A-Za-z]*[oO]\b|--output(?:=|\s)))/.test(cmd);
}

/** True when a path resolves into a different group's private folder. */
function escapesGroup(filePath: string, baseDir: string, groupsDir: string): boolean {
  if (!filePath) return false;
  const absolute = isAbsolute(filePath) ? resolve(filePath) : resolve(baseDir, filePath);
  const real = canonicalPath(absolute);
  const groupsRoot = canonicalPath(resolve(groupsDir));
  return isPathInside(groupsRoot, real) && !isPathInside(canonicalPath(resolve(baseDir)), real);
}

function searchRootAllowed(searchPath: string, baseDir: string, dataDir: string, groupFolder = 'main'): boolean {
  const absolute = isAbsolute(searchPath) ? resolve(searchPath) : resolve(baseDir, searchPath || '.');
  const real = canonicalPath(absolute);
  const base = canonicalPath(resolve(baseDir));
  const data = canonicalPath(resolve(dataDir));
  const downloads = groupFolder === 'main'
    ? join(data, 'downloads')
    : join(data, 'downloads', groupFolder);
  return isPathInside(base, real) ||
    isPathInside(downloads, real) ||
    isPathInside(join(data, 'tmp'), real);
}

function bashGroupEscape(cmd: string, baseDir: string, groupsDir: string): boolean {
  const cdTargets = bashCdTargets(cmd, baseDir);
  for (const token of bashTokens(cmd)) {
    for (const candidate of tokenCandidates(token, baseDir, cdTargets)) {
      if (escapesGroup(candidate, baseDir, groupsDir)) return true;
    }
  }
  return false;
}

// Bash can bypass Write/Edit/Read hooks, so apply the same path policy to every
// path-like token in a command. Read-only commands are checked against
// sensitive paths; commands that can write are checked against protected paths
// too. This catches relative traversal, `~` expansion, symlinked parents, and
// simple `cd` chains.
function findBashPathAccess(cmd: string, baseDir: string, dataDir: string): RegExp | null {
  const writes = commandWrites(cmd);
  const patterns = writes ? protectedPaths(dataDir) : [
    ...sensitivePaths(dataDir),
    new RegExp(`^${escapeRegExp(canonicalPath(resolve(dataDir)))}/memory\\.md$`),
    // Recursive readers must not start at the installation root; the root
    // contains .env and data alongside the intentionally readable source.
    new RegExp(`^${escapeRegExp(PROJECT_ROOT)}$`),
    /^\/$/,
  ];
  const helper = trustedHelperPath(cmd);
  let skippedHelper = false;
  const cdTargets = bashCdTargets(cmd, baseDir);
  for (const token of bashTokens(cmd)) {
    if (helper && !skippedHelper && isSamePathToken(token, helper, baseDir)) {
      skippedHelper = true;
      continue;
    }
    const candidates = tokenCandidates(token, baseDir, cdTargets);
    const hit = patterns.find(p => candidates.some(c => p.test(c)));
    if (hit) return hit;
  }
  return null;
}

/** Test helper: returns the first deny rule matching `cmd`, or null. */
export function findBashDeny(
  cmd: string,
  baseDir = join(PROJECT_ROOT, 'groups', 'main'),
  dataDir = DEFAULT_DATA_DIR,
  groupsDir = join(PROJECT_ROOT, 'groups'),
): RegExp | null {
  const normalized = normalizeCommand(cmd);
  return BASH_DENY.find(p => p.test(normalized)) ??
    findBashSelfWrite(normalized, baseDir) ??
    findBashPathAccess(normalized, baseDir, dataDir) ??
    (bashGroupEscape(normalized, baseDir, groupsDir) ? /group-isolation/ : null);
}

/** Test helper: returns the first sensitive-path pattern matching `p`, or null. */
export function findSensitivePath(p: string, dataDir = DEFAULT_DATA_DIR, groupFolder = 'main'): RegExp | null {
  return sensitivePaths(dataDir, groupFolder).find(r => r.test(p)) ?? null;
}

/** Test helper: returns the first protected-path pattern matching `p`, or null. */
export function findProtectedPath(p: string, dataDir = DEFAULT_DATA_DIR, groupFolder = 'main'): RegExp | null {
  return protectedPaths(dataDir, groupFolder).find(r => r.test(p)) ?? null;
}

/** Reject glob patterns that can escape their search root. */
export function isUnsafeGlob(pattern: string): boolean {
  const p = pattern.trim();
  if (!p) return false;
  if (/^(?:[\\/]|~|[A-Za-z]:[\\/])/.test(p)) return true;
  return p.split(/[\\/]/).some(part => part.includes('..')) || p.includes('~') || p.includes('$');
}

/** Test helper: does a Grep/Glob pattern target a sensitive filename? */
export function isSensitiveGlob(pattern: string): boolean {
  const normalized = pattern.replace(/\\/g, '/').toLowerCase();
  return [
    '.env', '/.ssh', 'credentials/', '/id_rsa', '/id_ed25519', '/id_ecdsa', '/id_dsa',
    '.pem', '.mcp.json', 'store.db', 'settings.json', 'memory.md',
  ].some(marker => normalized.includes(marker));
}

// Deny patterns for Bash commands — defense-in-depth layer.
// Primary security: systemd sandboxing + scoped sudoers + file path hooks.
// $() is allowed for legitimate CLI use (skills, jq, date, etc.).
const BASH_DENY = [
  // Shell injection / inline execution
  /\$\(\s*(curl|wget)\b/,              // subshell exfiltration
  /\$\(\s*(rm|dd|mv)\b/,              // subshell destructive
  /`[^`]+`/,                           // backtick execution
  /\|\s*(ba)?sh\b/,                    // pipe to shell
  /\|\s*zsh\b/,
  /\b(curl|wget)\b.*\|\s*(ba)?sh/,     // download-and-execute
  /\beval\b/,                          // eval
  /\b(?:ba|da|k|fi|z)?sh\s+-[a-z]*c\b/, // bash/dash/ksh/fish/zsh -c and combined flags (-lc)
  /\b(?:ba|da|k|fi|z)?sh\s+-[a-z]*c\S*/,// attached -c code after quote removal
  /\bpython[23]?\s+-c(?:\s|\S)/,       // python -c (attached or spaced)
  /\bperl\s+-[eE](?:\s|\S)/,            // perl -e/-E
  /\bnode\s+(?:-e|--eval)(?:\s|\S)/,   // node -e/--eval
  /\b(?:bun|deno|tsx)\s+(?:-e|eval)(?:\s|\S)/,
  /\bruby\s+-e(?:\s|\S)/,              // ruby -e
  /\bphp\s+-r(?:\s|\S)/,               // php -r
  /\$[(][^)]*(?:\.env|\.ssh|credentials|id_(?:rsa|ed25519|ecdsa|dsa)|\.mcp\.json|settings\.json|store\.db|memory\.md)/i,
  /\$[(]\s*</,                          // $(<file) read substitution

  // Reverse shells / exfiltration
  /\bnc\b.*-[elp]/,                    // netcat listeners
  /\bncat\b/,
  /\/dev\/(tcp|udp)\//,                // bash reverse shell
  /\bmkfifo\b/,                        // named pipe

  // Destructive operations
  /;\s*rm\s+-rf?\s/,                   // chained destructive rm
  /\brm\s+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+)*(?:\/|~|\$HOME)(?:\s|$)/,
  /\brm\s+(?:-[a-zA-Z]*[rf][a-zA-Z]*\s+)*\/(?:usr|var|etc|opt|home|root|bin|sbin|lib|boot|dev|proc|sys)(?:\s|$)/,
  /\bdd\b.*\bof=/,                     // disk write
  /\/dev\/(?:fd|mem|kmem|port)(?:\/|\s|$)/,

  // Secret access — block reading sensitive files via common viewers
  /\b(cat|less|more|head|tail|grep|rg|awk|sed)\b.*(\.(env|pem)\b|\/etc\/(shadow|passwd|gshadow|group)|id_(rsa|ed25519|ecdsa|dsa)|\.ssh\/|credentials\/|\.claude\/|\.aws\/|\.kube\/|\.config\/gcloud\/|\.mcp\.json|settings\.json|store\.db|memory\.md)/,
  /\bsed\b.*\.env/,
  /^\s*env\s*($|\|)/,                       // bare env or env piped (dumps all environment variables)
  /\bprintenv\b/,                            // printenv (any form — no legitimate agent use)

  // Critical system files — block all access via Bash (reads, writes, redirects)
  // Agent can still configure nginx, mysql, letsencrypt, systemd services, sysctl.d, sources.list.d
  // via `sudo bash setup.sh install-config <path>` which validates the target against an allowlist.
  /\/etc\/(shadow|passwd|group|gshadow)(-|\b)/,
  /\/etc\/sudoers(\.d)?\b/,
  /\/etc\/ssh\//,
  /\/etc\/pam\.d(\/|\b)/,
  /\/etc\/security(\/|\b)/,
  /\/etc\/ld\.so\.(preload|conf(\.d)?)(\/|\b)/,
  /\/etc\/profile(\.d)?(\/|\b)/,
  /\/etc\/bash\.bashrc\b/,
  /\/etc\/environment\b/,
  /\/etc\/cron\.(d|daily|hourly|monthly|weekly)(\/|\b)/,
  /\/etc\/crontab\b/,
  /\/etc\/hosts\b/,
  /\/etc\/resolv\.conf\b/,
  /\/etc\/hostname\b/,
  /\/etc\/fstab\b/,
  /\/etc\/nsswitch\.conf\b/,
  /\/etc\/sysctl\.conf\b/,
  /\/etc\/apt\/sources\.list(?!\.d)/,
  /\/etc\/apt\/trusted\.gpg/,
  /\/etc\/systemd\/system\/cakeagent/,

  // System administration — allow service management, protect critical services
  /\bsystemctl\b.*\bcakeagent\b/,
  /\bsystemctl\s+(stop|restart|start|disable|enable|mask|unmask|kill)\s+\S*\b(sshd?|networking)(\.service|\.socket)?\b/,
  /\bsystemctl\b.*\b(stop|disable)\b.*\b(nftables|firewalld|ufw|fail2ban)\b/,
  /\bsystemctl\b.*\bmask\b/,
  /\breboot\b/,
  /\bshutdown\b/,
  /\bpasswd\b/,
  /\busermod\b/,
  /\buseradd\b/,
  /\buserdel\b/,
  /\bvisudo\b/,

  // Filesystem security
  /\bchmod\b.*\.(ssh|env|pem)/,
  /\bchown\b.*\.(ssh|env|pem)/,
  // Firewall — allow rule management, block destructive operations
  /\bnft\s+flush\b/,
  /\bnft\s+delete\s+table\b/,
  /\biptables\s+-[FXZ]\b/,
  /\biptables\s+-P\b.*\bACCEPT\b/,
  /\b(nft|iptables)\b.*\bdport\s+22\b/,
  /\bufw\s+(--force\s+)?reset\b/,
  /\bufw\s+disable\b/,
  /\bufw\s+default\s+allow\b/,
  /\bufw\s+(allow|deny|limit|reject|delete)\b.*\b22(\/tcp)?\b/,
  /\bfirewall-cmd\s+.*--panic-on\b/,
  /\bfirewall-cmd\s+.*--remove-service=ssh\b/,
  /\bfirewall-cmd\s+.*--remove-port=22\b/,
  /\bfirewall-cmd\s+.*--set-default-zone=trusted\b/,
  /\bfail2ban-client\s+stop\b/,
  /\bfail2ban-client\s+unban\s+--all\b/,
  /\bnetfilter-persistent\s+flush\b/,
  /\biptables-restore\b/,
  /\bip6tables-restore\b/,

  // Managed data (skills/memory/settings) and the installation tree are
  // blocked by findBashPathAccess(), anchored to the configured data directory.

  // Enhanced validators — Unicode, control chars, process substitution, etc.
  /[\u00A0\u2000-\u200A\u2028\u2029\u202F\u205F\u3000]/,
  /[\x00-\x08\x0B\x0C\x0E-\x1F]/,
  /\bIFS\s*=/,
  /<\(/,
  />\(/,
  /\{[^}]*[;&|][^}]*\}/,
  /\/proc\/(self|\d+)\/environ/,
  /\b(zmodload|zpty|ztcp|zsocket|sysopen|sysread|syswrite)\b/,
  /\bjq\b.*@base64d/,
  /--\$[{(]/,
];

// Sensitive filenames that are never safe to read anywhere. Installation-
// specific state (settings.json, store.db, skills, memory) is added by
// `sensitivePaths()` so an unrelated user project named settings.json or
// data/skills is not blocked by over-broad global patterns.
const SENSITIVE_BASE_PATHS = [
  /(^|\/)\.env(\.[^/]*)?$/i,
  /(^|\/)\.ssh(\/|$)/i,
  /(^|\/)credentials(\/|$)/i,
  /(^|\/)id_(rsa|ed25519|ecdsa|dsa)(\.pub)?$/i,
  /\.pem$/i,
  /\/etc\/(shadow|passwd|group|gshadow)(-|$)/,
  /\/etc\/ssh(\/|$)/,
  /\/etc\/(?:letsencrypt\/(?:archive|keys)|ssl\/private)(\/|$)/,
  /\/proc\/(?:self|\d+)(?:\/task\/\d+)?\/(?:environ|root|cwd|fd|map_files|mem|maps|pagemap|kcore)(\/|$)/,
  /\/dev\/(?:fd|mem|kmem|port)(\/|$)/,
  /(^|\/)\.mcp\.json$/,
  /(^|\/)\.claude(\/|$)/,
  /(^|\/)\.aws(\/|$)/,
  /(^|\/)\.config\/gcloud(\/|$)/,
  /(^|\/)\.kube(\/|$)/,
  /(^|\/)\.docker\/config\.json$/,
  /(^|\/)\.git-credentials$/,
  /(^|\/)\.netrc$/,
  /(^|\/)conversations(\/|$)/i,
];

function sensitivePaths(dataDir: string, groupFolder = 'main'): RegExp[] {
  const data = escapeRegExp(canonicalPath(resolve(dataDir)));
  const patterns = [
    ...SENSITIVE_BASE_PATHS,
    new RegExp(`^${data}/settings\\.json$`),
    new RegExp(`^${data}/store\\.db(?:-wal|-shm)?$`),
    new RegExp(`^${data}/skills(?:/|$)`),
    // Bash can recurse over a directory and bypass exact-file patterns. Deny
    // the data root (except downloads/tmp) so `grep -r data` cannot read the
    // settings, database, memory, or archived conversations.
    new RegExp(`^${data}(?:/(?!downloads(?:/|$)|tmp(?:/|$)).*)?$`),
    /^\/etc$/,
  ];
  if (groupFolder !== 'main' && /^[a-zA-Z0-9_-]{1,50}$/.test(groupFolder)) {
    // Incoming files are partitioned by group. A group may read its own
    // downloads (and the shared tmp staging area), never another group's.
    const downloads = escapeRegExp(join(data, 'downloads'));
    patterns.push(new RegExp(`^${downloads}(?:/(?!${escapeRegExp(groupFolder)}(?:/|$)).*)?$`));
  }
  return patterns;
}

// Write/Edit is blocked for these paths. Install-tree protection is anchored
// to this project root so an unrelated user project at groups/x/src remains
// editable — only CakeAgent's own source is off-limits.
function protectedPaths(dataDir: string, groupFolder = 'main'): RegExp[] {
  const data = escapeRegExp(canonicalPath(resolve(dataDir)));
  return [
    ...sensitivePaths(dataDir, groupFolder),
    ...SELF_PROTECTED_PATHS,
    /(^|\/)CLAUDE\.md$/i,
    /(^|\/)\.claude(\/|$)/,
    /(^|\/)skills\/index\.json$/,
    new RegExp(`^${data}/skills/.+\\.md$`),
    new RegExp(`^${data}/memory\\.md$`),

    // Critical /etc/ paths — individual entries (replaces the blanket /etc/ block
    // so the agent can use install-config for non-critical /etc/ writes).
    /\/etc\/(shadow|passwd|group|gshadow)(-|$)/,
    /\/etc\/sudoers(\.d)?(\/|$)/,
    /\/etc\/ssh(\/|$)/,
    /\/etc\/pam\.d(\/|$)/,
    /\/etc\/security(\/|$)/,
    /\/etc\/ld\.so\.(preload|conf(\.d)?)(\/|$)/,
    /\/etc\/profile(\.d)?(\/|$)/,
    /\/etc\/bash\.bashrc$/,
    /\/etc\/environment$/,
    /\/etc\/cron\.(d|daily|hourly|monthly|weekly)(\/|$)/,
    /\/etc\/crontab$/,
    /\/etc\/hosts$/,
    /\/etc\/hostname$/,
    /\/etc\/resolv\.conf$/,
    /\/etc\/fstab$/,
    /\/etc\/nsswitch\.conf$/,
    /\/etc\/sysctl\.conf$/,
    /\/etc\/apt\/sources\.list$/,
    /\/etc\/apt\/trusted\.gpg/,
    /\/etc\/systemd\/system\/cakeagent/,
  ];
}

// Resolve a user-supplied path through symlinks and compare to the protected
// list. Relative paths are resolved against the agent's group folder, not the
// bot installer's process.cwd().
function resolvedPathBlocked(filePath: string, patterns: RegExp[], baseDir: string): RegExp | null {
  if (!filePath) return null;
  const absolute = isAbsolute(filePath) ? resolve(filePath) : resolve(baseDir, filePath);

  // Match against the raw and absolute paths first (fast, covers non-existent
  // targets of Write).
  const rawHit = patterns.find(p => p.test(filePath) || p.test(absolute));
  if (rawHit) return rawHit;

  // canonicalPath resolves every existing ancestor, so a symlinked parent
  // works even when several trailing directories do not exist yet.
  const real = canonicalPath(absolute);
  return patterns.find(p => p.test(real)) ?? null;
}

function deny(reason: string) {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse' as const,
      permissionDecision: 'deny' as const,
      permissionDecisionReason: reason,
    },
  };
}

function allow() {
  return {
    hookSpecificOutput: {
      hookEventName: 'PreToolUse' as const,
      permissionDecision: 'allow' as const,
    },
  };
}

export function createHooks(state: RunState, groupsDir = './groups', dataDir = DEFAULT_DATA_DIR) {
  const groupFolder = /^[a-zA-Z0-9_-]{1,50}$/.test(state.currentGroupFolder ?? '') ? state.currentGroupFolder! : 'main';
  const baseDir = join(resolve(groupsDir), groupFolder);
  const sensitive = sensitivePaths(dataDir, groupFolder);
  const protectedFiles = protectedPaths(dataDir, groupFolder);

  return {
    PreToolUse: [
      {
        // Constrained background runs (memory extraction) get a hard tool
        // allowlist. This is independent of the SDK's own permission handling.
        matcher: '.*',
        hooks: [async (input: HookInput) => {
          const toolName = 'tool_name' in input ? String(input.tool_name) : '';
          if (state.allowedTools) {
            if (!state.allowedTools.includes(toolName)) {
              logAudit('tool_denied', `${toolName || 'unknown'} (not allowed in this run)`);
              return deny('Tool not permitted in this maintenance run');
            }
            return allow();
          }
          // Do not emit an explicit allow for normal runs: that would bypass
          // the SDK permission layer. The specific hooks below still deny
          // unsafe operations and otherwise leave the decision untouched.
          return {};
        }],
      },
      {
        matcher: '^Bash$',
        hooks: [async (input: HookInput) => {
          const ti = 'tool_input' in input ? input.tool_input as { command?: string } : null;
          const command: string = ti?.command ?? '';
          const normalized = normalizeCommand(command);
          // Group chats are conversation scopes, not administrative shells.
          // A static command filter cannot contain `sudo` invoked from a
          // script/interpreter (awk, sed, a downloaded CLI, etc.), so groups
          // get no Bash tool at all. The SDK allowlist enforces the same rule.
          if (state.currentGroupFolder !== 'main') {
            logAudit('bash_denied', `bash disabled in group: ${command.slice(0, 300)}`);
            return deny('Bash is only available in the main chat');
          }
          const denied = BASH_DENY.find(p => p.test(normalized)) ??
            findBashSelfWrite(normalized, baseDir) ??
            findBashPathAccess(normalized, baseDir, dataDir) ??
            (bashGroupEscape(normalized, baseDir, groupsDir) ? /group-isolation/ : null);
          if (denied) {
            logAudit('bash_denied', command.slice(0, 500));
            return deny('Command matches a blocked pattern');
          }
          logAudit('bash_allowed', command.slice(0, 200));
          return allow();
        }],
      },
      {
        matcher: '^Read$',
        hooks: [async (input: HookInput) => {
          const filePath: string = ('tool_input' in input ? (input.tool_input as { file_path?: string })?.file_path : '') ?? '';
          if (resolvedPathBlocked(filePath, sensitive, baseDir) ||
              escapesGroup(filePath, baseDir, groupsDir)) {
            logAudit('read_denied', filePath);
            return deny('Sensitive file or another group\'s folder — access blocked');
          }
          return allow();
        }],
      },
      {
        matcher: '^Grep$',
        hooks: [async (input: HookInput) => {
          const ti = 'tool_input' in input ? input.tool_input as { path?: string; pattern?: string; glob?: string } : null;
          const searchPath = ti?.path ?? '';
          const glob = ti?.glob ?? ti?.pattern ?? '';
          if (resolvedPathBlocked(searchPath, sensitive, baseDir) ||
              escapesGroup(searchPath, baseDir, groupsDir) ||
              !searchRootAllowed(searchPath, baseDir, dataDir, groupFolder) ||
              isSensitiveGlob(glob) || isUnsafeGlob(glob)) {
            logAudit('grep_denied', `${searchPath} ${glob}`.trim());
            return deny('Search root is restricted to this group and its download/tmp folders');
          }
          return allow();
        }],
      },
      {
        matcher: '^Glob$',
        hooks: [async (input: HookInput) => {
          const ti = 'tool_input' in input ? input.tool_input as { path?: string; pattern?: string } : null;
          const searchPath = ti?.path ?? '';
          const glob = ti?.pattern ?? '';
          if (resolvedPathBlocked(searchPath, sensitive, baseDir) ||
              escapesGroup(searchPath, baseDir, groupsDir) ||
              !searchRootAllowed(searchPath, baseDir, dataDir, groupFolder) ||
              isSensitiveGlob(glob) || isUnsafeGlob(glob)) {
            logAudit('glob_denied', `${searchPath} ${glob}`.trim());
            return deny('Search root is restricted to this group and its download/tmp folders');
          }
          return allow();
        }],
      },
      {
        matcher: '^WebFetch$',
        hooks: [async (input: HookInput) => {
          const ti = 'tool_input' in input ? input.tool_input as { url?: string } : null;
          const url = ti?.url ?? '';
          const safe = isSafeOutboundUrl(url);
          if (!safe.ok) {
            logAudit('webfetch_denied', `${url.slice(0, 300)} (${safe.reason})`);
            return deny(`URL denied: ${safe.reason}`);
          }
          return allow();
        }],
      },
      {
        matcher: '^(Write|Edit|MultiEdit|NotebookEdit)$',
        hooks: [async (input: HookInput) => {
          const ti = 'tool_input' in input
            ? input.tool_input as { file_path?: string; notebook_path?: string }
            : null;
          const filePath: string = ti?.file_path ?? ti?.notebook_path ?? '';
          if (resolvedPathBlocked(filePath, protectedFiles, baseDir) ||
              escapesGroup(filePath, baseDir, groupsDir)) {
            logAudit('file_denied', filePath);
            return deny('Protected file or another group\'s folder — access blocked');
          }
          return allow();
        }],
      },
    ],
    PostToolUse: [],
    SubagentStart: [
      {
        matcher: '.*',
        hooks: [async (input: HookInput) => {
          const si = input as { agent_type?: string; agent_id?: string };
          logAudit('subagent_start', `type=${si.agent_type ?? 'unknown'} id=${si.agent_id ?? 'unknown'}`);
          return {};
        }],
      },
    ],
    PreCompact: [
      {
        matcher: '.*',
        hooks: [async (input: HookInput) => {
          try {
            const sessionId = input.session_id ?? 'unknown';
            const rawGroup = state.currentGroupFolder ?? 'main';
            const groupFolder = /^[a-zA-Z0-9_-]{1,50}$/.test(rawGroup) ? rawGroup : 'main';
            const chatId = state.currentChatId ?? '';
            const archiveDir = join(resolve(groupsDir), groupFolder, 'conversations');
            mkdirSync(archiveDir, { recursive: true });
            const date = new Date().toISOString().slice(0, 10);
            const safeSession = sessionId.replace(/[^a-zA-Z0-9_-]/g, '').slice(0, 32) || 'unknown';
            const filename = `${date}-${safeSession}-${Date.now()}.md`;
            const archivePath = join(archiveDir, filename);

            // Dump actual recent transcript from SQLite so the archive is searchable,
            // not a placeholder. Bounded at 500 messages to avoid runaway files.
            let body = '';
            if (chatId) {
              const recent = getMessagesSince(chatId, 0, 500, true);
              body = [...recent].reverse().map(m => {
                const iso = new Date(m.timestamp).toISOString();
                return `### ${iso} — ${m.sender_name}\n${(m.content ?? '').slice(0, 4000)}`;
              }).join('\n\n');
            }
            const header = `# Conversation archived ${new Date().toISOString()}\nSession: ${sessionId}\nGroup: ${groupFolder}\nChat: ${chatId || '(unknown)'}\n\n`;
            writeFileSync(archivePath, header + (body || '_(no transcript available — chat unknown)_\n'), { mode: 0o600 });

            // Signal this run to extract memory from the messages about to be lost.
            state.pendingMemoryExtraction = { groupFolder, chatId };
            logAudit('precompact', `Archived session ${sessionId} (${body.length} chars)`);
          } catch (err) {
            logAudit('precompact_error', (err as Error).message.slice(0, 200));
          }
          return {};
        }],
      },
    ],
  };
}
