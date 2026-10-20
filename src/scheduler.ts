import * as store from './store.js';
import { parseCronExpression, computeNextCronRun } from './cron.js';
import { MAX_SCHEDULE_INTERVAL_MS } from './types.js';
import type { ScheduledTask } from './types.js';
import { log } from './logger.js';

export function advanceScheduledTask(task: ScheduledTask, error?: string): void {
  const now = new Date();
  const lastRun = now.toISOString();
  const lastError = error ?? null;

  if (!task.recurring) {
    store.updateSchedule(task.id, { status: 'completed', lastRun, lastError } as Partial<ScheduledTask>);
    return;
  }

  if (task.scheduleType === 'cron') {
    const fields = parseCronExpression(task.scheduleValue);
    const next = fields ? computeNextCronRun(fields, now) : null;
    if (!next) {
      store.updateSchedule(task.id, { status: 'paused', lastRun, lastError: error ?? 'invalid cron expression' } as Partial<ScheduledTask>);
      log.warn({ context: 'scheduler', taskId: task.id, scheduleValue: task.scheduleValue }, 'Paused task (invalid cron)');
      return;
    }
    store.updateSchedule(task.id, { nextRun: next.toISOString(), lastRun, lastError } as Partial<ScheduledTask>);
    return;
  }

  const ms = Number(task.scheduleValue);
  if (!Number.isFinite(ms) || !Number.isInteger(ms) || ms <= 0 || ms > MAX_SCHEDULE_INTERVAL_MS) {
    store.updateSchedule(task.id, { status: 'paused', lastRun, lastError: error ?? 'invalid interval' } as Partial<ScheduledTask>);
    log.warn({ context: 'scheduler', taskId: task.id, scheduleValue: task.scheduleValue }, 'Paused task (invalid interval)');
    return;
  }
  store.updateSchedule(task.id, {
    nextRun: new Date(now.getTime() + ms).toISOString(),
    lastRun,
    lastError,
  } as Partial<ScheduledTask>);
}
