import { test } from 'node:test';
import assert from 'node:assert/strict';
import { parseCronExpression, computeNextCronRun, cronToHuman } from '../src/cron.js';

test('cron: parses basic 5-field expression', () => {
  const f = parseCronExpression('30 9 * * 1-5');
  assert.ok(f);
  assert.deepEqual(f!.minute, [30]);
  assert.deepEqual(f!.hour, [9]);
  assert.deepEqual(f!.dayOfWeek, [1, 2, 3, 4, 5]);
});

test('cron: rejects malformed input', () => {
  assert.equal(parseCronExpression(''), null);
  assert.equal(parseCronExpression('not a cron'), null);
  assert.equal(parseCronExpression('60 0 * * *'), null);      // minute out of range
  assert.equal(parseCronExpression('0 24 * * *'), null);      // hour out of range
  assert.equal(parseCronExpression('0 0 32 * *'), null);      // dom out of range
  assert.equal(parseCronExpression('0 0 * 13 *'), null);      // month out of range
  assert.equal(parseCronExpression('0 0 * * 8'), null);       // dow out of range
  assert.equal(parseCronExpression('*/0 * * * *'), null);     // step zero
  assert.equal(parseCronExpression('5-2 * * * *'), null);     // reversed range
});

test('cron: dow=7 aliases to Sunday (0)', () => {
  const f = parseCronExpression('0 0 * * 7');
  assert.ok(f);
  assert.deepEqual(f!.dayOfWeek, [0]);
});

test('cron: step and list syntax', () => {
  const f = parseCronExpression('*/15 0,12 * * *');
  assert.ok(f);
  assert.deepEqual(f!.minute, [0, 15, 30, 45]);
  assert.deepEqual(f!.hour, [0, 12]);
});

test('cron: @daily nickname', () => {
  const f = parseCronExpression('@daily');
  assert.ok(f);
  assert.deepEqual(f!.minute, [0]);
  assert.deepEqual(f!.hour, [0]);
  assert.equal(f!.dayOfMonth.length, 31);
});

test('cron: @hourly and @weekly nicknames', () => {
  const h = parseCronExpression('@hourly');
  assert.ok(h);
  assert.deepEqual(h!.minute, [0]);
  assert.equal(h!.hour.length, 24);

  const w = parseCronExpression('@weekly');
  assert.ok(w);
  assert.deepEqual(w!.dayOfWeek, [0]);
});

test('cron: month/day name aliases (JAN, MON, etc.)', () => {
  const f = parseCronExpression('0 9 * JAN MON-FRI');
  assert.ok(f);
  assert.deepEqual(f!.month, [1]);
  assert.deepEqual(f!.dayOfWeek, [1, 2, 3, 4, 5]);
});

test('cron: case-insensitive name aliases', () => {
  const f = parseCronExpression('0 0 * mar sun');
  assert.ok(f);
  assert.deepEqual(f!.month, [3]);
  assert.deepEqual(f!.dayOfWeek, [0]);
});

test('cron: computeNextCronRun — daily 9am', () => {
  const f = parseCronExpression('0 9 * * *')!;
  const from = new Date(2026, 3, 15, 8, 30, 0);  // 15 Apr 2026 08:30 local
  const next = computeNextCronRun(f, from);
  assert.ok(next);
  assert.equal(next!.getHours(), 9);
  assert.equal(next!.getMinutes(), 0);
  assert.equal(next!.getDate(), 15);
});

test('cron: computeNextCronRun rolls to next day when past', () => {
  const f = parseCronExpression('0 9 * * *')!;
  const from = new Date(2026, 3, 15, 10, 0, 0);
  const next = computeNextCronRun(f, from);
  assert.ok(next);
  assert.equal(next!.getDate(), 16);
});

test('cron: computeNextCronRun with DOM+DOW both constrained uses OR', () => {
  // 1st of month OR every Monday — standard cron semantics
  const f = parseCronExpression('0 0 1 * 1')!;
  // Tuesday 2026-04-14: next match should be Mon 2026-04-20 (by DOW)
  // or Fri 2026-05-01 (by DOM) — whichever comes first.
  const from = new Date(2026, 3, 14, 12, 0, 0);
  const next = computeNextCronRun(f, from);
  assert.ok(next);
  // Either 2026-04-20 (Mon) or earlier — must be before May 1.
  assert.ok(next!.getTime() < new Date(2026, 4, 2).getTime());
});

test('cron: returns null for impossible expressions', () => {
  // Feb 30 doesn't exist — should never match.
  const f = parseCronExpression('0 0 30 2 *')!;
  const next = computeNextCronRun(f, new Date(2026, 0, 1));
  assert.equal(next, null);
});

test('cron: finds February 29 across a leap-year gap', () => {
  const f = parseCronExpression('0 0 29 2 *')!;
  const next = computeNextCronRun(f, new Date(2025, 2, 1));
  assert.ok(next);
  assert.equal(next!.getMonth(), 1);
  assert.equal(next!.getDate(), 29);
  assert.equal(next!.getFullYear(), 2028);
});

test('cronToHuman: daily', () => {
  assert.equal(cronToHuman('0 9 * * *'), 'Every day at 9:00 AM');
});

test('cronToHuman: weekdays', () => {
  assert.equal(cronToHuman('30 8 * * 1-5'), 'Weekdays at 8:30 AM');
});

test('cronToHuman: every minute / every hour', () => {
  assert.equal(cronToHuman('*/1 * * * *'), 'Every minute');
  assert.equal(cronToHuman('*/5 * * * *'), 'Every 5 minutes');
  assert.equal(cronToHuman('0 * * * *'), 'Every hour');
});
