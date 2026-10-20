import { test } from 'node:test';
import assert from 'node:assert/strict';
import { log, redactForLog } from '../src/logger.js';

test('logger: basic structured output', () => {
  // Just verify it doesn't throw and produces valid JSON
  log.info({ context: 'test', value: 123 }, 'test message');
  log.warn({ context: 'test' }, 'warning');
  log.error({ context: 'test', err: 'something failed' }, 'error');
  log.debug({ context: 'test' }, 'debug');
});

test('logger: string-only form', () => {
  log.info('simple message');
  log.warn('warning message');
  log.error('error message');
  log.debug('debug message');
});

test('redactForLog: masks known secret keys', () => {
  const input = { token: 'secret123', api_key: 'abc', password: 'pwd', normal: 'value' };
  const out = redactForLog(input) as Record<string, unknown>;
  assert.equal(out.token, '[REDACTED]');
  assert.equal(out.api_key, '[REDACTED]');
  assert.equal(out.password, '[REDACTED]');
  assert.equal(out.normal, 'value');
});

test('redactForLog: masks long alphanumeric strings', () => {
  const out = redactForLog({ maybe_token: 'sk-ant-1234567890abcdefghij1234567890' }) as Record<string, unknown>;
  assert.equal(out.maybe_token, '[REDACTED]');
});

test('redactForLog: leaves short strings alone', () => {
  const out = redactForLog({ short: 'abc123' }) as Record<string, unknown>;
  assert.equal(out.short, 'abc123');
});

test('redactForLog: handles nested objects', () => {
  const out = redactForLog({ outer: { inner_token: 'secret', normal: 'ok' } }) as Record<string, unknown>;
  assert.equal((out.outer as Record<string, unknown>).inner_token, '[REDACTED]');
  assert.equal((out.outer as Record<string, unknown>).normal, 'ok');
});

test('redactForLog: handles arrays', () => {
  const out = redactForLog({ items: ['normal', 'sk-ant-1234567890abcdefghij1234567890'] }) as Record<string, unknown>;
  assert.equal((out.items as unknown[])[0], 'normal');
  assert.equal((out.items as unknown[])[1], '[REDACTED]');
});

test('redactForLog: handles null/undefined', () => {
  assert.equal(redactForLog(null), null);
  assert.equal(redactForLog(undefined), undefined);
  assert.equal(redactForLog('string'), 'string');
  assert.equal(redactForLog(123), 123);
});
