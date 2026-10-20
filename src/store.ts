import Database from 'better-sqlite3';
import { readFileSync, writeFileSync, existsSync, mkdirSync, renameSync, unlinkSync, lstatSync, openSync, fstatSync, closeSync, constants } from 'node:fs';
import { randomBytes } from 'node:crypto';
import { join } from 'node:path';
import type { IncomingMessage, RegisteredGroup, ScheduledTask, CakeSettings } from './types.js';
import {
  CakeSettingsSchema, DEFAULT_SETTINGS, normalizeSettings, redactSecrets,
  MAX_SKILL_BYTES, MAX_MEMORY_BYTES,
} from './types.js';
import { isPathInside, canonicalPath } from './security.js';
import { log } from './logger.js';

let db: Database.Database;
let dataDir: string;

export function initDb(dir: string): void {
  dataDir = dir;
  mkdirSync(dir, { recursive: true });
  db = new Database(join(dir, 'store.db'));
  db.pragma('journal_mode = WAL');

  db.exec(`
    CREATE TABLE IF NOT EXISTS messages (
      id TEXT PRIMARY KEY,
      chat_id TEXT NOT NULL,
      sender_id TEXT,
      sender_name TEXT,
      content TEXT,
      timestamp INTEGER NOT NULL,
      is_group INTEGER DEFAULT 0,
      seq INTEGER
    );
    CREATE INDEX IF NOT EXISTS idx_msg_chat ON messages(chat_id, timestamp);
    CREATE INDEX IF NOT EXISTS idx_msg_chat_seq ON messages(chat_id, seq);

    CREATE TABLE IF NOT EXISTS schedules (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      group_folder TEXT NOT NULL,
      chat_id TEXT NOT NULL,
      task TEXT NOT NULL,
      schedule_type TEXT NOT NULL,
      schedule_value TEXT NOT NULL,
      context_mode TEXT DEFAULT 'group',
      next_run TEXT,
      status TEXT DEFAULT 'active',
      last_run TEXT,
      last_error TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS groups (
      chat_id TEXT PRIMARY KEY,
      name TEXT NOT NULL,
      folder TEXT NOT NULL UNIQUE,
      trigger_word TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS sessions (
      group_folder TEXT PRIMARY KEY,
      session_id TEXT NOT NULL
    );

    CREATE TABLE IF NOT EXISTS rate_limits (
      key TEXT PRIMARY KEY,
      count INTEGER NOT NULL DEFAULT 0,
      window_start INTEGER NOT NULL
    );

    CREATE TABLE IF NOT EXISTS audit_log (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      event TEXT NOT NULL,
      detail TEXT,
      created_at TEXT NOT NULL DEFAULT (datetime('now'))
    );

    CREATE TABLE IF NOT EXISTS kv (
      key TEXT PRIMARY KEY,
      value TEXT NOT NULL
    );

    -- Monotonic message sequence. SQLite reuses rowids after the highest row is
    -- deleted (for example by retention pruning), which would make a persisted
    -- rowid cursor skip every new message. This table is never pruned, so its
    -- AUTOINCREMENT values remain strictly increasing.
    CREATE TABLE IF NOT EXISTS message_seq (
      id INTEGER PRIMARY KEY AUTOINCREMENT
    );
  `);

  // Migrations: add columns for cron scheduling / stable system-task identity
  const migrations = [
    `ALTER TABLE schedules ADD COLUMN recurring INTEGER DEFAULT 1`,
    `ALTER TABLE schedules ADD COLUMN system INTEGER DEFAULT 0`,
    `ALTER TABLE schedules ADD COLUMN system_key TEXT`,
    `ALTER TABLE messages ADD COLUMN seq INTEGER`,
  ];
  for (const sql of migrations) {
    try { db.exec(sql); } catch { /* column already exists */ }
  }

  // Backfill seq in insertion order for databases created before it existed,
  // then advance message_seq past the highest assigned value. Existing
  // chat_cursor KV values were rowids, which equal the backfilled seq values.
  db.exec(`UPDATE messages SET seq = rowid WHERE seq IS NULL`);
  const maxSeq = (db.prepare(`SELECT COALESCE(MAX(seq), 0) AS n FROM messages`).get() as { n: number }).n;
  const seqState = db.prepare(`SELECT seq FROM sqlite_sequence WHERE name = 'message_seq'`).get() as { seq: number } | undefined;
  if ((seqState && maxSeq > seqState.seq) || (!seqState && maxSeq > 0)) {
    db.prepare(`INSERT INTO message_seq (id) VALUES (?)`).run(maxSeq);
  }

  // A previous crash or manual edit must not make startup fail on the unique
  // system-key index. Keep the preferred row (active first, newest id).
  const duplicateKeys = db.prepare(
    `SELECT system_key FROM schedules WHERE system_key IS NOT NULL
     GROUP BY system_key HAVING COUNT(*) > 1`,
  ).all() as Array<{ system_key: string }>;
  for (const { system_key } of duplicateKeys) {
    const rows = db.prepare(
      `${SCHEDULE_SELECT} WHERE system_key = ?
       ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'paused' THEN 1 ELSE 2 END, id DESC`,
    ).all(system_key) as ScheduledTask[];
    for (const row of rows.slice(1)) db.prepare(`DELETE FROM schedules WHERE id = ?`).run(row.id);
  }

  db.exec(`
    CREATE INDEX IF NOT EXISTS idx_sched_due ON schedules(status, next_run);
    CREATE INDEX IF NOT EXISTS idx_audit_created ON audit_log(created_at);
    CREATE UNIQUE INDEX IF NOT EXISTS idx_sched_system_key
      ON schedules(system_key) WHERE system_key IS NOT NULL;
  `);

  // FTS5 virtual table for message search. Unindexed columns keep them queryable
  // for filtering without tokenising. Triggers keep it in sync automatically.
  // Wrapped in try/catch because FTS5 requires the SQLite build to include it —
  // if unavailable, search_messages degrades to a LIKE query.
  try {
    db.exec(`
      CREATE VIRTUAL TABLE IF NOT EXISTS messages_fts USING fts5(
        content,
        sender_name UNINDEXED,
        chat_id UNINDEXED,
        timestamp UNINDEXED,
        message_id UNINDEXED,
        tokenize = 'unicode61 remove_diacritics 2'
      );

      CREATE TRIGGER IF NOT EXISTS messages_ai AFTER INSERT ON messages BEGIN
        INSERT INTO messages_fts (content, sender_name, chat_id, timestamp, message_id)
        VALUES (new.content, new.sender_name, new.chat_id, new.timestamp, new.id);
      END;

      CREATE TRIGGER IF NOT EXISTS messages_ad AFTER DELETE ON messages BEGIN
        DELETE FROM messages_fts WHERE message_id = old.id;
      END;

      CREATE TRIGGER IF NOT EXISTS messages_au AFTER UPDATE ON messages BEGIN
        DELETE FROM messages_fts WHERE message_id = old.id;
        INSERT INTO messages_fts (content, sender_name, chat_id, timestamp, message_id)
        VALUES (new.content, new.sender_name, new.chat_id, new.timestamp, new.id);
      END;
    `);
    ftsAvailable = true;
    // Backfill FTS from existing messages on first run (idempotent via rebuild).
    const ftsCount = db.prepare(`SELECT COUNT(*) as n FROM messages_fts`).get() as { n: number };
    const msgCount = db.prepare(`SELECT COUNT(*) as n FROM messages`).get() as { n: number };
    if (ftsCount.n === 0 && msgCount.n > 0) {
      db.exec(`INSERT INTO messages_fts (content, sender_name, chat_id, timestamp, message_id)
        SELECT content, sender_name, chat_id, timestamp, id FROM messages`);
    }
  } catch (err) {
    log.warn({ context: 'store', err: (err as Error).message }, 'FTS5 unavailable, search will use LIKE fallback');
    ftsAvailable = false;
  }
}

let ftsAvailable = false;
export function hasFts(): boolean { return ftsAvailable; }

// --- Messages ---

export function saveMessage(msg: IncomingMessage, content?: string): void {
  const existing = db.prepare(`SELECT seq FROM messages WHERE id = ?`).get(msg.id) as { seq: number } | undefined;
  if (existing) {
    // A message may be updated after it was first stored (e.g. reply context
    // enrichment). Keep its original sequence so conversation order survives.
    db.prepare(`UPDATE messages SET content = ? WHERE id = ?`).run(content ?? msg.text ?? '', msg.id);
    return;
  }
  const seq = Number(db.prepare(`INSERT INTO message_seq DEFAULT VALUES`).run().lastInsertRowid);
  db.prepare(
    `INSERT INTO messages (id, chat_id, sender_id, sender_name, content, timestamp, is_group, seq)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(msg.id, msg.chatId, msg.senderId, msg.senderName, content ?? msg.text ?? '', msg.timestamp, msg.isGroup ? 1 : 0, seq);
}

export function saveOutgoing(chatId: string, content: string, timestamp: number): void {
  const id = `out_${timestamp}_${Math.random().toString(36).slice(2, 8)}`;
  const seq = Number(db.prepare(`INSERT INTO message_seq DEFAULT VALUES`).run().lastInsertRowid);
  db.prepare(
    `INSERT OR IGNORE INTO messages (id, chat_id, sender_id, sender_name, content, timestamp, is_group, seq)
     VALUES (?, ?, 'assistant', 'assistant', ?, ?, 0, ?)`
  ).run(id, chatId, content, timestamp, seq);
}

export interface StoredMessage {
  rowId: number;
  sender_name: string;
  content: string;
  timestamp: number;
}

// `rowId` is the monotonic message_seq value, not SQLite's reusable rowid.
// Assistant output is excluded by default: the SDK session already contains
// it, and replaying it as a user-role message corrupts the next prompt.
// Startup/history variant: return the oldest rows in the window so a large
// backlog drains in order instead of skipping its beginning.
export function getMessagesSinceAsc(
  chatId: string,
  since: number,
  limit = 50,
  includeAssistant = false,
): StoredMessage[] {
  return db.prepare(
    `SELECT seq as rowId, sender_name, content, timestamp FROM messages
     WHERE chat_id = ? AND timestamp >= ? ${includeAssistant ? '' : "AND COALESCE(sender_id, '') != 'assistant'"}
     ORDER BY seq ASC LIMIT ?`
  ).all(chatId, since, limit) as StoredMessage[];
}

export function getMessagesSince(
  chatId: string,
  since: number,
  limit = 50,
  includeAssistant = false,
): StoredMessage[] {
  const assistantClause = includeAssistant ? '' : ` AND COALESCE(sender_id, '') != 'assistant'`;
  return db.prepare(
    `SELECT seq as rowId, sender_name, content, timestamp FROM messages
     WHERE chat_id = ? AND timestamp > ?${assistantClause}
     ORDER BY seq DESC LIMIT ?`
  ).all(chatId, since, limit) as StoredMessage[];
}

// Returns the *oldest* unseen rows first so a burst larger than `limit` is
// drained in order instead of jumping the cursor over the middle of the burst.
export function getMessagesAfterRow(chatId: string, rowId: number, limit = 50): StoredMessage[] {
  return db.prepare(
    `SELECT seq as rowId, sender_name, content, timestamp FROM messages
     WHERE chat_id = ? AND seq > ? AND COALESCE(sender_id, '') != 'assistant'
     ORDER BY seq ASC LIMIT ?`
  ).all(chatId, rowId, limit) as StoredMessage[];
}

// Full-text search across stored messages. Uses FTS5 if available, falls back
// to a simple LIKE scan. Returns most recent first.
export function searchMessages(
  query: string,
  opts: { chatId?: string; since?: number; limit?: number } = {},
): Array<{ sender_name: string; content: string; timestamp: number; chat_id: string }> {
  const limit = Math.min(Math.max(1, opts.limit ?? 20), 200);
  const since = opts.since ?? 0;

  if (ftsAvailable) {
    // FTS5 MATCH — split into words, quote each term, and AND them together.
    // This avoids MATCH syntax errors while giving predictable "all words"
    // semantics (an exact phrase query would be surprising for multi-word
    // searches and differs from the LIKE fallback).
    const terms = query.replace(/["']/g, ' ').trim().split(/\s+/).filter(Boolean).slice(0, 20);
    if (terms.length === 0) return [];
    const matchExpr = terms.map(t => `"${t}"`).join(' AND ');
    const where: string[] = [`messages_fts MATCH ?`];
    const vals: unknown[] = [matchExpr];
    if (opts.chatId) { where.push(`chat_id = ?`); vals.push(opts.chatId); }
    if (since > 0) { where.push(`timestamp > ?`); vals.push(since); }
    try {
      return db.prepare(
        `SELECT content, sender_name, chat_id, timestamp FROM messages_fts
         WHERE ${where.join(' AND ')} ORDER BY timestamp DESC LIMIT ?`
      ).all(...vals, limit) as Array<{ sender_name: string; content: string; timestamp: number; chat_id: string }>;
    } catch {
      // Fall through to LIKE on malformed queries.
    }
  }

  const terms = query.trim().split(/\s+/).filter(Boolean).slice(0, 20);
  if (terms.length === 0) return [];
  const where: string[] = terms.map(() => `content LIKE ? ESCAPE '\\'`);
  const vals: unknown[] = terms.map(t => `%${t.replace(/[%_\\]/g, '\\$&')}%`);
  if (opts.chatId) { where.push(`chat_id = ?`); vals.push(opts.chatId); }
  if (since > 0) { where.push(`timestamp > ?`); vals.push(since); }
  return db.prepare(
    `SELECT content, sender_name, chat_id, timestamp FROM messages
     WHERE ${where.join(' AND ')} ORDER BY timestamp DESC LIMIT ?`
  ).all(...vals, limit) as Array<{ sender_name: string; content: string; timestamp: number; chat_id: string }>;
}

// --- Groups ---

// Registering a chat is idempotent. Folder takeover is explicit: without
// `allowFolderTakeover`, a different chat cannot claim an existing folder.
// Startup passes the flag for the configured main chat; the agent-facing tool
// does not, which prevents a prompt-injected `register_group` call from
// hijacking another chat's folder (and therefore its files/context).
export function registerGroup(
  group: RegisteredGroup,
  opts: { allowFolderTakeover?: boolean } = {},
): void {
  const byFolder = db.prepare(`SELECT chat_id FROM groups WHERE folder = ?`).get(group.folder) as
    { chat_id: string } | undefined;

  const apply = db.transaction(() => {
    if (byFolder && byFolder.chat_id !== group.chatId) {
      if (!opts.allowFolderTakeover) {
        throw new Error(`Folder "${group.folder}" is already registered to another chat.`);
      }
      db.prepare(`DELETE FROM groups WHERE folder = ?`).run(group.folder);
    }
    db.prepare(
      `INSERT INTO groups (chat_id, name, folder, trigger_word) VALUES (?, ?, ?, ?)
       ON CONFLICT(chat_id) DO UPDATE SET
         name = excluded.name, folder = excluded.folder, trigger_word = excluded.trigger_word`
    ).run(group.chatId, group.name, group.folder, group.trigger);
  });
  apply();
}

export function getGroups(): RegisteredGroup[] {
  return db.prepare(`SELECT chat_id as chatId, name, folder, trigger_word as trigger FROM groups`).all() as RegisteredGroup[];
}

export function getGroupByChatId(chatId: string): RegisteredGroup | undefined {
  return db.prepare(`SELECT chat_id as chatId, name, folder, trigger_word as trigger FROM groups WHERE chat_id = ?`).get(chatId) as RegisteredGroup | undefined;
}

// --- Sessions ---

export function getSession(groupFolder: string): string | null {
  const row = db.prepare(`SELECT session_id FROM sessions WHERE group_folder = ?`).get(groupFolder) as { session_id: string } | undefined;
  return row?.session_id ?? null;
}

export function setSession(groupFolder: string, sessionId: string): void {
  db.prepare(`INSERT OR REPLACE INTO sessions (group_folder, session_id) VALUES (?, ?)`).run(groupFolder, sessionId);
}

// --- Schedules ---

export function addSchedule(task: Omit<ScheduledTask, 'id' | 'lastRun' | 'lastError' | 'createdAt'>): number {
  const result = db.prepare(
    `INSERT INTO schedules (group_folder, chat_id, task, schedule_type, schedule_value, context_mode, next_run, status, recurring, system, system_key)
     VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
  ).run(
    task.groupFolder, task.chatId, task.task, task.scheduleType, task.scheduleValue,
    task.contextMode, task.nextRun, task.status, task.recurring ? 1 : 0,
    task.system ? 1 : 0, task.systemKey ?? null,
  );
  return Number(result.lastInsertRowid);
}

const SCHEDULE_SELECT = `SELECT id, group_folder as groupFolder, chat_id as chatId, task,
  schedule_type as scheduleType, schedule_value as scheduleValue,
  context_mode as contextMode, next_run as nextRun, status,
  COALESCE(recurring, 1) as recurring, COALESCE(system, 0) as system,
  system_key as systemKey,
  last_run as lastRun, last_error as lastError, created_at as createdAt
  FROM schedules`;

export function getDueSchedules(now: string): ScheduledTask[] {
  return db.prepare(`${SCHEDULE_SELECT} WHERE next_run <= ? AND status = 'active'`).all(now) as ScheduledTask[];
}

export function getAllSchedules(): ScheduledTask[] {
  return db.prepare(`${SCHEDULE_SELECT} WHERE status != 'completed'`).all() as ScheduledTask[];
}

const SCHEDULE_COLUMNS: Record<string, string> = {
  task: 'task', scheduleType: 'schedule_type', scheduleValue: 'schedule_value',
  contextMode: 'context_mode', nextRun: 'next_run', status: 'status',
  lastRun: 'last_run', lastError: 'last_error', recurring: 'recurring', system: 'system',
  systemKey: 'system_key',
};

export function updateSchedule(id: number, fields: Partial<ScheduledTask>): void {
  const sets: string[] = [];
  const vals: unknown[] = [];
  for (const [k, v] of Object.entries(fields)) {
    const col = SCHEDULE_COLUMNS[k];
    if (!col) continue;
    sets.push(`${col} = ?`);
    vals.push(v);
  }
  if (sets.length === 0) return;
  vals.push(id);
  db.prepare(`UPDATE schedules SET ${sets.join(', ')} WHERE id = ?`).run(...vals);
}

export function deleteSchedule(id: number): void {
  db.prepare(`DELETE FROM schedules WHERE id = ?`).run(id);
}

export function getMissedSchedules(now: string): ScheduledTask[] {
  return db.prepare(`${SCHEDULE_SELECT} WHERE next_run < ? AND status = 'active'`).all(now) as ScheduledTask[];
}

export function getScheduleByTask(taskDescription: string): ScheduledTask | undefined {
  return db.prepare(`${SCHEDULE_SELECT} WHERE task = ? AND status = 'active' LIMIT 1`).get(taskDescription) as ScheduledTask | undefined;
}

export function getScheduleByTaskAnyStatus(taskDescription: string): ScheduledTask | undefined {
  return db.prepare(
    `${SCHEDULE_SELECT} WHERE task = ?
     ORDER BY CASE status WHEN 'active' THEN 0 WHEN 'paused' THEN 1 ELSE 2 END, id DESC
     LIMIT 1`,
  ).get(taskDescription) as ScheduledTask | undefined;
}

export function getScheduleBySystemKey(systemKey: string): ScheduledTask | undefined {
  return db.prepare(`${SCHEDULE_SELECT} WHERE system_key = ? LIMIT 1`).get(systemKey) as ScheduledTask | undefined;
}

export function getScheduleById(id: number): ScheduledTask | undefined {
  return db.prepare(`${SCHEDULE_SELECT} WHERE id = ? LIMIT 1`).get(id) as ScheduledTask | undefined;
}

// --- Rate Limits ---

export function checkRateLimit(key: string, max: number, windowMs: number): boolean {
  const now = Date.now();
  const row = db.prepare(`SELECT count, window_start FROM rate_limits WHERE key = ?`).get(key) as { count: number; window_start: number } | undefined;

  if (!row || now - row.window_start > windowMs) {
    db.prepare(`INSERT OR REPLACE INTO rate_limits (key, count, window_start) VALUES (?, 1, ?)`).run(key, now);
    return true;
  }
  if (row.count >= max) return false;
  db.prepare(`UPDATE rate_limits SET count = count + 1 WHERE key = ?`).run(key);
  return true;
}

// --- Audit ---

export function logAudit(event: string, detail?: string): void {
  // Always redact known secret substrings before persisting. Cheap and defence
  // in depth — callers should still avoid logging credentials on purpose.
  const safeDetail = detail != null ? redactSecrets(detail).slice(0, 2000) : null;
  db.prepare(`INSERT INTO audit_log (event, detail) VALUES (?, ?)`).run(event, safeDetail);
}

function toSqlTimestamp(value: string): string {
  // audit_log.created_at is stored by SQLite as "YYYY-MM-DD HH:MM:SS" (UTC).
  // Accept ISO timestamps from callers and compare in the same format.
  return value.includes('T') ? value.slice(0, 19).replace('T', ' ') : value;
}

export function listAuditEvents(opts: { event?: string; since?: string; limit?: number } = {}):
  Array<{ id: number; event: string; detail: string | null; created_at: string }> {
  const limit = Math.min(Math.max(1, opts.limit ?? 50), 500);
  const where: string[] = [];
  const vals: unknown[] = [];
  if (opts.event) { where.push(`event = ?`); vals.push(opts.event); }
  if (opts.since) { where.push(`created_at > ?`); vals.push(toSqlTimestamp(opts.since)); }
  const sql = `SELECT id, event, detail, created_at FROM audit_log
    ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    ORDER BY id DESC LIMIT ?`;
  return db.prepare(sql).all(...vals, limit) as Array<{ id: number; event: string; detail: string | null; created_at: string }>;
}

// --- Settings ---

export function loadSettings(): CakeSettings {
  const path = join(dataDir, 'settings.json');
  if (!existsSync(path)) {
    saveSettings(DEFAULT_SETTINGS);
    return { ...DEFAULT_SETTINGS };
  }
  try {
    if (lstatSync(path).isSymbolicLink()) {
      log.error({ context: 'store', path }, 'settings.json is a symlink — refusing to read it');
      return { ...DEFAULT_SETTINGS };
    }
    const raw: unknown = JSON.parse(readFileSync(path, 'utf-8'));
    const { settings, issues } = normalizeSettings(raw);
    if (issues.length > 0) {
      log.warn({ context: 'store', issues }, 'settings.json contained invalid values — repaired');
      // Heal the file so the warning doesn't repeat on every invocation.
      writeAtomic(path, JSON.stringify(settings, null, 2));
    }
    return settings;
  } catch (err) {
    log.error({ context: 'store', err: (err as Error).message }, 'settings.json is corrupt — using defaults');
    return { ...DEFAULT_SETTINGS };
  }
}

export function writeAtomic(filePath: string, data: string, mode = 0o600): void {
  // Use an unpredictable exclusive path. A predictable `.tmp` name lets the
  // agent place a symlink there, causing a later settings/index write to
  // overwrite a file of its choosing.
  const tmp = `${filePath}.${process.pid}.${randomBytes(8).toString('hex')}.tmp`;
  try {
    writeFileSync(tmp, data, { mode, flag: 'wx' });
    renameSync(tmp, filePath);
  } catch (err) {
    try { unlinkSync(tmp); } catch { /* ignore */ }
    throw err;
  }
}

export function saveSettings(settings: CakeSettings): void {
  const parsed = CakeSettingsSchema.safeParse(settings);
  if (!parsed.success) {
    throw new Error(`Refusing to save invalid settings: ${parsed.error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ')}`);
  }
  writeAtomic(join(dataDir, 'settings.json'), JSON.stringify(parsed.data, null, 2));
}

// --- Pruning ---

export function pruneOldData(retentionDays = 30): void {
  const cutoff = Date.now() - retentionDays * 24 * 60 * 60_000;
  db.prepare(`DELETE FROM messages WHERE timestamp < ?`).run(cutoff);
  db.prepare(`DELETE FROM audit_log WHERE created_at < datetime('now', ? || ' days')`).run(-retentionDays);
  db.prepare(`DELETE FROM rate_limits WHERE window_start < ?`).run(cutoff);
  // Keep the sequence table bounded. sqlite_sequence retains the high-water
  // mark, so pruning old rows cannot make ids get reused.
  db.prepare(`DELETE FROM message_seq WHERE id < (SELECT COALESCE(MAX(id), 0) - 1000 FROM message_seq)`).run();
}

export function countActiveSchedules(): number {
  const row = db.prepare(`SELECT COUNT(*) as count FROM schedules WHERE status = 'active'`).get() as { count: number };
  return row.count;
}

// --- Skills ---

// `sha` and `ref` pin the commit the skill body was fetched at, so the
// content can't silently change under us between installs. `summary` is the
// first non-empty line of the skill body, used for the lazy-loaded skill
// index injected into every prompt.
interface SkillMeta {
  owner: string;
  repo: string;
  skill: string;
  installedAt: string;
  sha?: string;
  ref?: string;
  summary?: string;
}

export function loadSkillIndex(): Record<string, SkillMeta> {
  const path = join(dataDir, 'skills', 'index.json');
  if (!existsSync(path)) return {};
  try {
    if (lstatSync(path).isSymbolicLink()) {
      log.error({ context: 'store', path }, 'skills/index.json is a symlink — refusing to read it');
      return {};
    }
    const raw: unknown = JSON.parse(readFileSync(path, 'utf-8'));
    if (!raw || typeof raw !== 'object' || Array.isArray(raw)) return {};
    const out: Record<string, SkillMeta> = Object.create(null) as Record<string, SkillMeta>;
    for (const [name, value] of Object.entries(raw as Record<string, unknown>)) {
      if (!/^[a-zA-Z0-9_-]{1,100}$/.test(name)) continue;
      if (['__proto__', 'prototype', 'constructor'].includes(name)) continue;
      if (!value || typeof value !== 'object' || Array.isArray(value)) continue;
      const meta = value as Record<string, unknown>;
      if (typeof meta.owner !== 'string' || typeof meta.repo !== 'string' ||
          typeof meta.skill !== 'string' || typeof meta.installedAt !== 'string') continue;
      out[name] = {
        owner: meta.owner,
        repo: meta.repo,
        skill: meta.skill,
        installedAt: meta.installedAt,
        ...(typeof meta.sha === 'string' ? { sha: meta.sha } : {}),
        ...(typeof meta.ref === 'string' ? { ref: meta.ref } : {}),
        ...(typeof meta.summary === 'string' ? { summary: meta.summary } : {}),
      };
    }
    return out;
  } catch (err) {
    log.error({ context: 'store', err: (err as Error).message }, 'skills/index.json is corrupt — treating as empty');
    return {};
  }
}

export function saveSkillIndex(index: Record<string, SkillMeta>): void {
  const dir = join(dataDir, 'skills');
  mkdirSync(dir, { recursive: true });
  writeAtomic(join(dir, 'index.json'), JSON.stringify(index, null, 2));
}

// Lazy-loaded skill index — returns only a one-line summary per skill so the
// whole catalogue fits in a few hundred tokens. The agent calls `read_skill`
// to fetch a full body on demand.
export function loadSkillSummaries(): string {
  const dir = join(dataDir, 'skills');
  if (!existsSync(dir)) return '';
  const index = loadSkillIndex();
  const names = Object.keys(index);
  if (names.length === 0) return '';
  const lines = names.map(name => {
    const meta = index[name]!;
    const summary = (meta.summary?.trim() || '(no description)').replace(/[\r\n]+/g, ' ');
    return `- ${name} — ${summary.slice(0, 140)}`;
  });
  return `Installed skills (call read_skill(name) for full body):\n${lines.join('\n')}`;
}

export function readSkill(name: string): string | null {
  if (!/^[a-zA-Z0-9_-]{1,100}$/.test(name)) return null;
  const skillsDir = resolveSkillsDir();
  const mdPath = join(skillsDir, `${name}.md`);
  const real = canonicalPath(mdPath);
  // A symlink inside skills/ must not turn read_skill into an arbitrary-file
  // reader (and host-side edits are possible even if the agent cannot write).
  // O_NOFOLLOW also closes the race where the path is swapped to a symlink
  // after canonicalPath ran.
  if (!isPathInside(skillsDir, real) || !existsSync(real)) return null;
  let fd: number;
  try {
    fd = openSync(real, constants.O_RDONLY | constants.O_NOFOLLOW);
  } catch {
    return null;
  }
  try {
    const st = fstatSync(fd);
    if (!st.isFile() || st.size > MAX_SKILL_BYTES) return null;
    return readFileSync(fd, 'utf-8');
  } catch {
    return null;
  } finally {
    closeSync(fd);
  }
}

function resolveSkillsDir(): string {
  return canonicalPath(join(dataDir, 'skills'));
}

// --- Key-Value ---

export function getKv(key: string): string | null {
  const row = db.prepare(`SELECT value FROM kv WHERE key = ?`).get(key) as { value: string } | undefined;
  return row?.value ?? null;
}

export function setKv(key: string, value: string): void {
  db.prepare(`INSERT OR REPLACE INTO kv (key, value) VALUES (?, ?)`).run(key, value);
}

// --- Audit Helpers ---

export function hasRecentAuditEvent(event: string, sinceMs: number): boolean {
  // SQLite's datetime('now') uses "YYYY-MM-DD HH:MM:SS", not ISO "…T…Z".
  // Comparing against toISOString() made recent events invisible for the whole
  // window (the string always sorted below the stored timestamp). Timestamps
  // have one-second precision, so use >= to avoid losing an event that landed
  // in the same second as the cutoff.
  const cutoff = new Date(Date.now() - sinceMs).toISOString().slice(0, 19).replace('T', ' ');
  const row = db.prepare(`SELECT 1 FROM audit_log WHERE event = ? AND created_at >= ? LIMIT 1`).get(event, cutoff);
  return !!row;
}

// --- Cleanup ---

export const MAX_MEMORY_SIZE = MAX_MEMORY_BYTES;

export function closeDb(): void {
  db?.close();
}
