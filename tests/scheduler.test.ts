import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import * as store from '../src/store.js';
import { advanceScheduledTask } from '../src/scheduler.js';
import type { ScheduledTask } from '../src/types.js';

let tmp: string;
before(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cakeagent-scheduler-test-'));
  store.initDb(tmp);
});
after(() => {
  store.closeDb();
  rmSync(tmp, { recursive: true, force: true });
});

function add(overrides: Partial<ScheduledTask>): number {
  return store.addSchedule({
    groupFolder: 'main',
    chatId: 'chat1',
    task: 'test task',
    scheduleType: 'cron',
    scheduleValue: '*/5 * * * *',
    contextMode: 'isolated',
    nextRun: new Date(Date.now() - 60_000).toISOString(),
    status: 'active',
    recurring: true,
    system: false,
    ...overrides,
  } as Omit<ScheduledTask, 'id' | 'lastRun' | 'lastError' | 'createdAt'>);
}

test('scheduler: failed recurring cron still advances and records the error', () => {
  const id = add({ task: 'cron-failure' });
  const task = store.getScheduleByTaskAnyStatus('cron-failure')!;
  advanceScheduledTask(task, 'boom');
  const updated = store.getScheduleByTaskAnyStatus('cron-failure')!;
  assert.equal(updated.status, 'active');
  assert.equal(updated.lastError, 'boom');
  assert.ok(new Date(updated.nextRun).getTime() > Date.now());
  assert.ok(updated.id === id);
});

test('scheduler: failed interval still advances', () => {
  add({ task: 'interval-failure', scheduleType: 'interval', scheduleValue: '60000', nextRun: new Date(Date.now() - 1000).toISOString() });
  const task = store.getScheduleByTaskAnyStatus('interval-failure')!;
  advanceScheduledTask(task, 'network');
  const updated = store.getScheduleByTaskAnyStatus('interval-failure')!;
  assert.equal(updated.status, 'active');
  assert.equal(updated.lastError, 'network');
  assert.ok(new Date(updated.nextRun).getTime() > Date.now() + 30_000);
});

test('scheduler: invalid interval pauses instead of retrying forever', () => {
  add({ task: 'bad-interval', scheduleType: 'interval', scheduleValue: '0' });
  const task = store.getScheduleByTaskAnyStatus('bad-interval')!;
  advanceScheduledTask(task, 'bad');
  const updated = store.getScheduleByTaskAnyStatus('bad-interval')!;
  assert.equal(updated.status, 'paused');
  assert.equal(updated.lastError, 'bad');
});

test('scheduler: invalid cron pauses', () => {
  add({ task: 'bad-cron', scheduleValue: 'not cron' });
  const task = store.getScheduleByTaskAnyStatus('bad-cron')!;
  advanceScheduledTask(task, 'bad');
  const updated = store.getScheduleByTaskAnyStatus('bad-cron')!;
  assert.equal(updated.status, 'paused');
  assert.equal(updated.lastError, 'bad');
});

test('scheduler: one-shot completes after a failed attempt', () => {
  add({ task: 'once-failure', scheduleType: 'once', scheduleValue: new Date().toISOString(), recurring: false });
  const task = store.getScheduleByTaskAnyStatus('once-failure')!;
  advanceScheduledTask(task, 'failed once');
  const updated = store.getScheduleByTaskAnyStatus('once-failure')!;
  assert.equal(updated.status, 'completed');
  assert.equal(updated.lastError, 'failed once');
});
