/** Minimal structured logger — JSON lines to stdout/stderr.
 * No external deps, no configuration. Log levels: debug, info, warn, error.
 * Use `log.debug({ key: val }, 'message')` for structured fields.
 * In production, pipe stdout/stderr to a log shipper (journald, Loki, etc.). */

type LogLevel = 'debug' | 'info' | 'warn' | 'error';

interface LogEntry {
  timestamp: string;
  level: LogLevel;
  message: string;
  fields?: Record<string, unknown>;
}

const levelOrder: Record<LogLevel, number> = { debug: 0, info: 1, warn: 2, error: 3 };
const currentLevel: LogLevel = (process.env.LOG_LEVEL as LogLevel) ?? 'info';

function shouldLog(level: LogLevel): boolean {
  return levelOrder[level] >= levelOrder[currentLevel];
}

function formatEntry(level: LogLevel, message: string, fields?: Record<string, unknown>): string {
  const entry: LogEntry = {
    timestamp: new Date().toISOString(),
    level,
    message,
  };
  if (fields && Object.keys(fields).length > 0) entry.fields = fields;
  return JSON.stringify(entry);
}

export const log = {
  debug: (fields: Record<string, unknown> | string, message?: string) => {
    if (!shouldLog('debug')) return;
    if (typeof fields === 'string') console.debug(formatEntry('debug', fields));
    else console.debug(formatEntry('debug', message ?? '', fields));
  },
  info: (fields: Record<string, unknown> | string, message?: string) => {
    if (!shouldLog('info')) return;
    if (typeof fields === 'string') console.info(formatEntry('info', fields));
    else console.info(formatEntry('info', message ?? '', fields));
  },
  warn: (fields: Record<string, unknown> | string, message?: string) => {
    if (!shouldLog('warn')) return;
    if (typeof fields === 'string') console.warn(formatEntry('warn', fields));
    else console.warn(formatEntry('warn', message ?? '', fields));
  },
  error: (fields: Record<string, unknown> | string, message?: string) => {
    if (!shouldLog('error')) return;
    if (typeof fields === 'string') console.error(formatEntry('error', fields));
    else console.error(formatEntry('error', message ?? '', fields));
  },
};

/** Redact known secret patterns from an object before logging. */
export function redactForLog(obj: unknown): unknown {
  if (obj === null || obj === undefined) return obj;
  if (typeof obj === 'string') {
    // Heuristic: long alphanumeric strings might be tokens (e.g., sk-ant-..., ghp_..., etc.)
    if (obj.length > 20 && /[A-Za-z0-9_-]{20,}/.test(obj)) {
      return '[REDACTED]';
    }
    return obj;
  }
  if (Array.isArray(obj)) return obj.map(redactForLog);
  if (typeof obj !== 'object') return obj;
  const out: Record<string, unknown> = {};
  const secretKeys = ['token', 'key', 'secret', 'password', 'authorization', 'auth', 'api', 'credential'];
  for (const [k, v] of Object.entries(obj)) {
    const kl = k.toLowerCase();
    if (secretKeys.some(s => kl.includes(s))) {
      out[k] = '[REDACTED]';
    } else {
      out[k] = redactForLog(v);
    }
  }
  return out;
}