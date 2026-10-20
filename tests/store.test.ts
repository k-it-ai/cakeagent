import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync, readFileSync, writeFileSync, symlinkSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as store from '../src/store.js';
import type { IncomingMessage } from '../src/types.js';
import { DEFAULT_SETTINGS } from '../src/types.js';

let tmp: string;

before(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cakeagent-test-'));
  store.initDb(tmp);
});

after(() => {
  store.closeDb();
  rmSync(tmp, { recursive: true, force: true });
});

function msg(overrides: Partial<IncomingMessage> = {}): IncomingMessage {
  return {
    id: `id_${Math.random().toString(36).slice(2)}`,
    text: 'hello',
    senderId: 'user1',
    senderName: 'Alice',
    chatId: 'chat1',
    timestamp: Date.now(),
    isGroup: false,
    ...overrides,
  };
}

test('store: saveMessage + getMessagesSince roundtrip', () => {
  const t = Date.now();
  store.saveMessage(msg({ id: 'm1', text: 'hi there', timestamp: t }));
  store.saveMessage(msg({ id: 'm2', text: 'second msg', timestamp: t + 100 }));
  const rows = store.getMessagesSince('chat1', t - 1, 10);
  assert.equal(rows.length, 2);
  assert.equal(rows[0]!.content, 'second msg');   // DESC
  assert.equal(rows[1]!.content, 'hi there');
});

test('store: searchMessages finds FTS / LIKE hits', () => {
  store.saveMessage(msg({ id: 'm3', text: 'I love pineapple pizza', chatId: 'chat2', timestamp: Date.now() }));
  const hits = store.searchMessages('pineapple');
  assert.ok(hits.length >= 1);
  assert.ok(hits.some(h => h.content?.includes('pineapple')));
});

test('store: searchMessages respects chatId filter', () => {
  store.saveMessage(msg({ id: 'm4', text: 'unique-marker-xyz', chatId: 'chat-other', timestamp: Date.now() }));
  const all = store.searchMessages('unique-marker-xyz');
  const filtered = store.searchMessages('unique-marker-xyz', { chatId: 'chat1' });
  assert.ok(all.length >= 1);
  assert.equal(filtered.length, 0);
});

test('store: searchMessages survives malformed FTS input', () => {
  // Double-quote injection attempts shouldn't throw — sanitizer strips them.
  const hits = store.searchMessages('"""');
  assert.ok(Array.isArray(hits));
});

test('store: rate limit — within window blocks over max', () => {
  const key = `rl_${Math.random()}`;
  assert.equal(store.checkRateLimit(key, 3, 60_000), true);
  assert.equal(store.checkRateLimit(key, 3, 60_000), true);
  assert.equal(store.checkRateLimit(key, 3, 60_000), true);
  assert.equal(store.checkRateLimit(key, 3, 60_000), false);  // over limit
});

test('store: audit log redacts secrets in detail', () => {
  store.logAudit('test_event', 'leak sk-ant-1234567890abcdefghij1234567890 done');
  const rows = store.listAuditEvents({ event: 'test_event', limit: 5 });
  assert.ok(rows.length >= 1);
  const latest = rows[0]!;
  assert.ok(!latest.detail!.includes('sk-ant-1234567890abcdefghij'));
  assert.ok(latest.detail!.includes('[REDACTED]'));
});

test('store: listAuditEvents filters by event', () => {
  store.logAudit('filter_a', 'first');
  store.logAudit('filter_b', 'second');
  const a = store.listAuditEvents({ event: 'filter_a', limit: 10 });
  assert.ok(a.every(r => r.event === 'filter_a'));
});

test('store: skill index loads and saves', () => {
  store.saveSkillIndex({
    outlook: {
      owner: 'dandcg', repo: 'claude-skills', skill: 'outlook',
      installedAt: '2026-04-15', sha: 'abc123def456', summary: 'Email integration',
    },
  });
  const idx = store.loadSkillIndex();
  assert.equal(idx.outlook?.sha, 'abc123def456');
  assert.equal(idx.outlook?.summary, 'Email integration');
});

// --- Group registration ---

test('store: registerGroup + getGroupByChatId roundtrip', () => {
  store.registerGroup({ chatId: 'g1', name: 'Test', folder: 'test-group', trigger: 'hey bot' });
  const g = store.getGroupByChatId('g1');
  assert.ok(g);
  assert.equal(g!.folder, 'test-group');
  assert.equal(g!.trigger, 'hey bot');
  assert.equal(g!.name, 'Test');
});

test('store: registerGroup with empty trigger (main group pattern)', () => {
  store.registerGroup({ chatId: 'main1', name: 'Main', folder: 'main', trigger: '' });
  const g = store.getGroupByChatId('main1');
  assert.ok(g);
  assert.equal(g!.trigger, '');
  assert.equal(g!.folder, 'main');
});

test('store: registerGroup is idempotent (same chatId overwrites)', () => {
  store.registerGroup({ chatId: 'idem1', name: 'V1', folder: 'idem-folder', trigger: 'v1' });
  store.registerGroup({ chatId: 'idem1', name: 'V2', folder: 'idem-folder', trigger: 'v2' });
  const g = store.getGroupByChatId('idem1');
  assert.equal(g!.name, 'V2');
  assert.equal(g!.trigger, 'v2');
});

test('store: registerGroup handles chatId change for same folder', () => {
  store.registerGroup({ chatId: 'old-chat', name: 'Main', folder: 'main-switch', trigger: '' });
  assert.ok(store.getGroupByChatId('old-chat'));
  assert.throws(() => {
    store.registerGroup({ chatId: 'new-chat', name: 'Main', folder: 'main-switch', trigger: '' });
  }, /already registered/);
  store.registerGroup(
    { chatId: 'new-chat', name: 'Main', folder: 'main-switch', trigger: '' },
    { allowFolderTakeover: true },
  );
  assert.equal(store.getGroupByChatId('old-chat'), undefined);
  assert.ok(store.getGroupByChatId('new-chat'));
  assert.equal(store.getGroupByChatId('new-chat')!.folder, 'main-switch');
});

test('store: getGroupByChatId returns undefined for unknown chat', () => {
  assert.equal(store.getGroupByChatId('nonexistent-chat-999'), undefined);
});

test('store: getGroups returns all registered groups', () => {
  store.registerGroup({ chatId: 'list1', name: 'A', folder: 'list-a', trigger: '' });
  store.registerGroup({ chatId: 'list2', name: 'B', folder: 'list-b', trigger: 'hey' });
  const all = store.getGroups();
  assert.ok(all.some(g => g.chatId === 'list1'));
  assert.ok(all.some(g => g.chatId === 'list2'));
});

// --- Sessions ---

test('store: getSession returns null when no session exists', () => {
  assert.equal(store.getSession('no-such-group'), null);
});

test('store: setSession + getSession roundtrip', () => {
  store.setSession('sess-group', 'session-abc-123');
  assert.equal(store.getSession('sess-group'), 'session-abc-123');
});

test('store: setSession overwrites previous session', () => {
  store.setSession('overwrite-group', 'old-session');
  store.setSession('overwrite-group', 'new-session');
  assert.equal(store.getSession('overwrite-group'), 'new-session');
});

test('store: setSession with empty string clears session', () => {
  store.setSession('clear-group', 'some-session');
  store.setSession('clear-group', '');
  assert.equal(store.getSession('clear-group'), '');
});

// --- Schedule management ---

test('store: addSchedule + getScheduleByTask roundtrip', () => {
  store.addSchedule({
    groupFolder: 'main', chatId: 'sched1', task: 'unique-test-task-abc',
    scheduleType: 'cron', scheduleValue: '0 9 * * *', contextMode: 'isolated',
    nextRun: new Date(Date.now() + 60_000).toISOString(), status: 'active',
    recurring: true, system: false,
  });
  const found = store.getScheduleByTask('unique-test-task-abc');
  assert.ok(found);
  assert.equal(found!.scheduleType, 'cron');
  assert.equal(found!.scheduleValue, '0 9 * * *');
  assert.equal(found!.recurring, 1); // SQLite returns integer
  assert.equal(found!.status, 'active');
});

test('store: getScheduleById returns active and completed rows', () => {
  const id = store.addSchedule({
    groupFolder: 'main', chatId: '1', task: 'by id', scheduleType: 'once',
    scheduleValue: new Date().toISOString(), contextMode: 'isolated',
    nextRun: new Date().toISOString(), status: 'active', recurring: false, system: false,
  });
  assert.equal(store.getScheduleById(id)?.id, id);
  store.updateSchedule(id, { status: 'completed' });
  assert.equal(store.getScheduleById(id)?.status, 'completed');
});
test('store: updateSchedule changes status', () => {
  const id = store.addSchedule({
    groupFolder: 'main', chatId: 'sched2', task: 'pause-me-task',
    scheduleType: 'cron', scheduleValue: '0 8 * * *', contextMode: 'isolated',
    nextRun: new Date(Date.now() + 60_000).toISOString(), status: 'active',
    recurring: true, system: true,
  });
  store.updateSchedule(id, { status: 'paused' } as any);
  const after = store.getScheduleByTask('pause-me-task');
  assert.equal(after, undefined); // getScheduleByTask only finds active
});

test('store: updateSchedule changes cron value and nextRun', () => {
  const id = store.addSchedule({
    groupFolder: 'main', chatId: 'sched3', task: 'update-cron-task',
    scheduleType: 'cron', scheduleValue: '0 8 * * *', contextMode: 'isolated',
    nextRun: '2026-04-17T08:00:00Z', status: 'active',
    recurring: true, system: true,
  });
  store.updateSchedule(id, { scheduleValue: '30 9 * * *', nextRun: '2026-04-17T09:30:00Z' } as any);
  const t = store.getScheduleByTask('update-cron-task');
  assert.ok(t);
  assert.equal(t!.scheduleValue, '30 9 * * *');
  assert.equal(t!.nextRun, '2026-04-17T09:30:00Z');
});

test('store: getDueSchedules returns tasks with nextRun <= now', () => {
  const past = new Date(Date.now() - 60_000).toISOString();
  const future = new Date(Date.now() + 3600_000).toISOString();
  store.addSchedule({
    groupFolder: 'main', chatId: 'due1', task: 'due-past-task',
    scheduleType: 'once', scheduleValue: '0', contextMode: 'isolated',
    nextRun: past, status: 'active', recurring: false, system: false,
  });
  store.addSchedule({
    groupFolder: 'main', chatId: 'due2', task: 'due-future-task',
    scheduleType: 'once', scheduleValue: '0', contextMode: 'isolated',
    nextRun: future, status: 'active', recurring: false, system: false,
  });
  const due = store.getDueSchedules(new Date().toISOString());
  assert.ok(due.some(t => t.task === 'due-past-task'));
  assert.ok(!due.some(t => t.task === 'due-future-task'));
});

test('store: getMissedSchedules returns overdue active tasks', () => {
  const past = new Date(Date.now() - 120_000).toISOString();
  store.addSchedule({
    groupFolder: 'main', chatId: 'miss1', task: 'missed-task-xyz',
    scheduleType: 'once', scheduleValue: '0', contextMode: 'isolated',
    nextRun: past, status: 'active', recurring: false, system: false,
  });
  const missed = store.getMissedSchedules(new Date().toISOString());
  assert.ok(missed.some(t => t.task === 'missed-task-xyz'));
});

test('store: deleteSchedule removes a task', () => {
  const id = store.addSchedule({
    groupFolder: 'main', chatId: 'del1', task: 'delete-me-task',
    scheduleType: 'once', scheduleValue: '0', contextMode: 'isolated',
    nextRun: new Date(Date.now() + 60_000).toISOString(), status: 'active',
    recurring: false, system: false,
  });
  store.deleteSchedule(id);
  assert.equal(store.getScheduleByTask('delete-me-task'), undefined);
});

test('store: countActiveSchedules counts only active tasks', () => {
  const before = store.countActiveSchedules();
  const id = store.addSchedule({
    groupFolder: 'main', chatId: 'cnt1', task: 'count-test-task',
    scheduleType: 'cron', scheduleValue: '0 0 * * *', contextMode: 'isolated',
    nextRun: new Date(Date.now() + 60_000).toISOString(), status: 'active',
    recurring: true, system: false,
  });
  assert.equal(store.countActiveSchedules(), before + 1);
  store.updateSchedule(id, { status: 'completed' } as any);
  assert.equal(store.countActiveSchedules(), before);
});

test('store: getAllSchedules excludes completed tasks', () => {
  const id = store.addSchedule({
    groupFolder: 'main', chatId: 'all1', task: 'all-sched-test',
    scheduleType: 'once', scheduleValue: '0', contextMode: 'isolated',
    nextRun: new Date().toISOString(), status: 'active',
    recurring: false, system: false,
  });
  assert.ok(store.getAllSchedules().some(t => t.task === 'all-sched-test'));
  store.updateSchedule(id, { status: 'completed' } as any);
  assert.ok(!store.getAllSchedules().some(t => t.task === 'all-sched-test'));
});

// --- KV store ---

test('store: getKv returns null for missing key', () => {
  assert.equal(store.getKv('nonexistent-key-xyz'), null);
});

test('store: setKv + getKv roundtrip', () => {
  store.setKv('test-key', 'test-value');
  assert.equal(store.getKv('test-key'), 'test-value');
});

test('store: setKv overwrites previous value', () => {
  store.setKv('overwrite-key', 'old');
  store.setKv('overwrite-key', 'new');
  assert.equal(store.getKv('overwrite-key'), 'new');
});


// --- Regression coverage: sequence cursor, settings healing, audit recency ---

test('store: getMessagesAfterRow is oldest-first and sequence survives pruning', () => {
  const chat = `cursor-${Date.now()}`;
  const t = Date.now();
  for (let i = 0; i < 3; i++) {
    store.saveMessage(msg({ id: `${chat}-${i}`, chatId: chat, text: `m${i}`, timestamp: t + i }));
  }
  const first = store.getMessagesAfterRow(chat, 0, 2);
  assert.equal(first.length, 2);
  assert.equal(first[0]!.content, 'm0');
  assert.equal(first[1]!.content, 'm1');
  const cursor = first[first.length - 1]!.rowId;

  // Delete the highest row (the shape of retention pruning) and verify a new
  // message still gets a higher sequence than the persisted cursor.
  const last = store.getMessagesAfterRow(chat, cursor, 10).at(-1)!;
  store.saveMessage(msg({ id: `${chat}-old`, chatId: chat, text: 'old', timestamp: Date.now() - 40 * 24 * 3600_000 }));
  store.pruneOldData(30);
  store.saveMessage(msg({ id: `${chat}-new`, chatId: chat, text: 'new', timestamp: Date.now() }));
  const after = store.getMessagesAfterRow(chat, Math.max(cursor, last.rowId), 10);
  assert.equal(after.length, 1);
  assert.equal(after[0]!.content, 'new');
  assert.ok(after[0]!.rowId > cursor);
});

test('store: loadSettings repairs invalid fields and preserves valid ones', () => {
  store.saveSettings({ ...DEFAULT_SETTINGS, assistantName: 'Keeper', allowedSenders: ['1'] });
  const path = join(tmp, 'settings.json');
  writeFileSync(path, JSON.stringify({ assistantName: 'Keeper', model: 'bogus', rateLimitMax: 0 }));
  const loaded = store.loadSettings();
  assert.equal(loaded.assistantName, 'Keeper');
  assert.equal(loaded.model, DEFAULT_SETTINGS.model);
  assert.equal(loaded.rateLimitMax, DEFAULT_SETTINGS.rateLimitMax);
  const healed = JSON.parse(readFileSync(path, 'utf-8'));
  assert.equal(healed.model, DEFAULT_SETTINGS.model);
  assert.equal(healed.rateLimitMax, DEFAULT_SETTINGS.rateLimitMax);
  store.saveSettings(DEFAULT_SETTINGS);
});

test('store: settings symlink is refused', () => {
  const path = join(tmp, 'settings.json');
  const target = join(tmp, 'settings-real.json');
  writeFileSync(target, JSON.stringify(DEFAULT_SETTINGS));
  rmSync(path, { force: true });
  symlinkSync(target, path);
  const loaded = store.loadSettings();
  assert.equal(loaded.assistantName, DEFAULT_SETTINGS.assistantName);
  rmSync(path, { force: true });
  symlinkSync(target, path); // still a symlink; remove before the next test writes settings
  rmSync(path, { force: true });
  store.saveSettings(DEFAULT_SETTINGS);
});

test('store: hasRecentAuditEvent uses SQLite timestamp format', () => {
  store.logAudit('recent_marker', 'now');
  assert.equal(store.hasRecentAuditEvent('recent_marker', 60_000), true);
  assert.equal(store.hasRecentAuditEvent('never_logged_marker', 60_000), false);
});
