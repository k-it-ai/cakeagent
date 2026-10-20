import * as z from 'zod';

// === Messages ===

export interface IncomingMessage {
  id: string;
  text?: string;
  voiceFileId?: string;
  photoFileId?: string;
  documentFileId?: string;
  documentName?: string;
  senderId: string;
  senderName: string;
  chatId: string;
  timestamp: number;
  isGroup: boolean;
  replyTo?: {
    text?: string;
    senderName?: string;
  };
}

export interface OutgoingMessage {
  chatId: string;
  text: string;
}

// === Channels ===

export interface Channel {
  name: string;
  poll(signal: AbortSignal): AsyncGenerator<TelegramUpdate>;
  send(chatId: string, text: string): Promise<void>;
  sendFile(chatId: string, filePath: string, caption?: string): Promise<void>;
  sendVoice(chatId: string, audio: Buffer): Promise<void>;
  startTyping(chatId: string): void;
  stopTyping(): void;
  downloadFile(fileId: string): Promise<Buffer>;
  sendSettingsKeyboard(chatId: string, settings: CakeSettings): Promise<number>;
  updateSettingsKeyboard(chatId: string, messageId: number, settings: CakeSettings): Promise<void>;
  answerCallback(callbackId: string, text?: string): Promise<void>;
  setCommands(commands: BotCommand[]): Promise<void>;
}

export interface BotCommand {
  command: string;
  description: string;
}

export interface TelegramUpdate {
  type: 'message' | 'callback_query';
  message?: IncomingMessage;
  callbackQuery?: CallbackQuery;
}

export interface CallbackQuery {
  id: string;
  chatId: string;
  messageId: number;
  data: string;
  senderId: string;
}

// === Groups ===

export interface RegisteredGroup {
  name: string;
  folder: string;
  trigger: string;
  chatId: string;
}

// === Tasks ===

export interface ScheduledTask {
  id: number;
  groupFolder: string;
  chatId: string;
  task: string;
  scheduleType: 'interval' | 'once' | 'cron';
  scheduleValue: string;
  contextMode: 'group' | 'isolated';
  nextRun: string;
  status: 'active' | 'paused' | 'completed';
  recurring: boolean;
  system: boolean;
  systemKey?: string | null;
  lastRun: string | null;
  lastError: string | null;
  createdAt: string;
}

// === Agent ===

export interface AgentRunParams {
  prompt: string;
  groupFolder: string;
  chatId: string;
  sessionId?: string;
}

// === Settings ===

export interface CakeSettings {
  assistantName: string;
  triggerPattern: string;
  model: string;
  thinkingLevel: string;
  voiceReceive: boolean;
  voiceSend: boolean;
  voiceSttModel: string;
  voiceTtsVoice: string;
  allowedSenders: string[];
  rateLimitMax: number;
  rateLimitWindow: number;
  agentTimeoutMs: number;
  morningCheckinCron: string;
  dreamCron: string;
  memoryExtractionEnabled: boolean;
  memoryExtractionInterval: number;
}

export const DEFAULT_SETTINGS: CakeSettings = {
  assistantName: 'CakeAgent',
  triggerPattern: '@CakeAgent',
  model: 'claude-sonnet-4-6',
  thinkingLevel: 'low',
  voiceReceive: false,
  voiceSend: false,
  voiceSttModel: 'base',
  voiceTtsVoice: 'en-US-AriaNeural',
  allowedSenders: [],
  rateLimitMax: 10,
  rateLimitWindow: 60_000,
  agentTimeoutMs: 300_000,
  morningCheckinCron: '57 8 * * *',
  dreamCron: '23 3 * * *',
  memoryExtractionEnabled: true,
  memoryExtractionInterval: 5,
};

export const INJECTION_PATTERNS = [
  /ignore\s+(all\s+)?(previous|prior)\s+(instructions?|prompts?)/i,
  /disregard\s+(all\s+)?(previous|prior)/i,
  /you\s+are\s+now\s+(a|an)\s+/i,
  /system\s*:\s*(prompt|override|command)/i,
  /\[System\s*Message\]/i,
  // Role/tag spoofing: "Assistant:" / "User:" line prefixes used to fake turn boundaries
  /^\s*(assistant|user|system|tool|tool_use|tool_result)\s*:/im,
  // XML/tag injection — fake SDK message wrappers in user content
  /<\/?(system|tool_use|tool_result|function_calls|parameter|assistant|user)\b[^>]*>/i,
  // ASCII-art / box-drawing runs used to smuggle instructions past scanners
  /[\u2580-\u259F\u2500-\u257F█▓▒░]{6,}/,
  // Common jailbreak framings
  /\b(developer|debug|admin|root)\s+mode\s+(on|enabled|activated)/i,
  /\boverride\s+(all\s+)?safety/i,
];

export const CREDENTIAL_PATTERNS = [
  /(api[_-]?key|token|secret|password|authorization)\s*[=:]\s*\S{20,}/i,
  /\b(sk-ant-|sk-|ghp_|gho_|xoxb-|xoxp-|glpat-)[a-zA-Z0-9_-]{20,}/,
];

// Shared sanitizer — strip lines matching known-bad patterns before storing or loading
// user-influenced content (memory.md, skills, etc.).
export function sanitizeMemory(content: string): string {
  return content.split('\n').filter(line =>
    !INJECTION_PATTERNS.some(p => p.test(line)) &&
    !CREDENTIAL_PATTERNS.some(p => p.test(line))
  ).join('\n');
}

// Redact known API-key prefixes from arbitrary strings before writing to
// audit_log / stdout. Conservative: only replace the secret span, not the
// surrounding context, so the log stays diagnostic.
const SECRET_SUBSTRING_RE = /(sk-ant-[a-zA-Z0-9_-]{20,}|sk-[a-zA-Z0-9_-]{20,}|ghp_[a-zA-Z0-9_-]{20,}|gho_[a-zA-Z0-9_-]{20,}|glpat-[a-zA-Z0-9_-]{20,}|xox[bpoas]-[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16}|AIza[0-9A-Za-z_-]{20,}|ya29\.[0-9A-Za-z_-]{20,})/g;
const KV_SECRET_RE = /(api[_-]?key|token|secret|password|authorization|bearer)(\s*[=:]\s*)(\S{16,})/ig;

export function redactSecrets(s: string): string {
  if (!s) return s;
  return s
    .replace(SECRET_SUBSTRING_RE, '[REDACTED]')
    .replace(KV_SECRET_RE, (_m, k, sep) => `${k}${sep}[REDACTED]`);
}

export const VALID_MODELS = new Set(['claude-haiku-4-5-20251001', 'claude-sonnet-4-6', 'claude-opus-4-6']);
export const VALID_THINKING_LEVELS = new Set(['off', 'low', 'medium', 'high']);
export const VALID_TTS_VOICE_RE = /^[a-z]{2,3}-[A-Z]{2,4}-\w+Neural$/;
export const VALID_STT_MODEL_RE = /^[a-z0-9-]{1,32}$/;
export const MAX_SKILL_BYTES = 50 * 1024;
export const MAX_MEMORY_BYTES = 50 * 1024;
export const MAX_SCHEDULE_INTERVAL_MS = 365 * 24 * 60 * 60_000;

// Runtime validation for settings loaded from disk or changed by the agent.
// Every field is validated independently so one bad value cannot reset the
// entire configuration to defaults.
export const CakeSettingsSchema = z.object({
  assistantName: z.string().trim().min(1).max(100).regex(/^[^\r\n]+$/, 'must be a single line'),
  triggerPattern: z.string().max(100).regex(/^[^\r\n]*$/, 'must be a single line'),
  model: z.string().refine(v => VALID_MODELS.has(v), 'unsupported model'),
  thinkingLevel: z.string().refine(v => VALID_THINKING_LEVELS.has(v), 'unsupported thinking level'),
  voiceReceive: z.boolean(),
  voiceSend: z.boolean(),
  voiceSttModel: z.string().regex(VALID_STT_MODEL_RE, 'invalid STT model name'),
  voiceTtsVoice: z.string().regex(VALID_TTS_VOICE_RE, 'invalid TTS voice'),
  allowedSenders: z.array(z.string().trim().min(1).max(64).regex(/^[^\r\n]+$/, 'must be a single line')).max(1000),
  rateLimitMax: z.number().int().min(1).max(10_000),
  rateLimitWindow: z.number().int().min(1_000).max(86_400_000),
  agentTimeoutMs: z.number().int().min(10_000).max(3_600_000),
  morningCheckinCron: z.string().max(100),
  dreamCron: z.string().max(100),
  memoryExtractionEnabled: z.boolean(),
  memoryExtractionInterval: z.number().int().min(1).max(1000),
});

export function normalizeSettings(raw: unknown): { settings: CakeSettings; issues: string[] } {
  const issues: string[] = [];
  const source = raw && typeof raw === 'object' && !Array.isArray(raw)
    ? { ...(raw as Record<string, unknown>) }
    : {};

  // Migrate legacy single `voice` toggle → split toggles.
  if ('voice' in source && !('voiceReceive' in source)) {
    source.voiceReceive = source.voice;
    source.voiceSend = source.voice;
    delete source.voice;
  }

  const settings = { ...DEFAULT_SETTINGS, allowedSenders: [...DEFAULT_SETTINGS.allowedSenders] } as CakeSettings;
  const shape = CakeSettingsSchema.shape as unknown as Record<string, z.ZodTypeAny>;
  for (const key of Object.keys(DEFAULT_SETTINGS) as Array<keyof CakeSettings>) {
    const value = source[key];
    if (value === undefined || value === null) continue;
    const result = shape[key]!.safeParse(value);
    if (result.success) {
      (settings as unknown as Record<string, unknown>)[key] = result.data;
    } else {
      issues.push(`${key}: ${result.error.issues[0]?.message ?? 'invalid value'}`);
    }
  }
  return { settings, issues };
}

// === Run State ===

export interface ScheduleOp {
  action: 'create';
  task: Omit<ScheduledTask, 'id' | 'lastRun' | 'lastError' | 'createdAt'>;
}

export interface PendingFile {
  chatId: string;
  filePath: string;
  caption?: string;
}

export interface RunState {
  pendingMessages: OutgoingMessage[];
  pendingFiles: PendingFile[];
  pendingSchedules: ScheduleOp[];
  currentGroupFolder?: string;
  currentChatId?: string;
  // Optional hard allowlist for background runs (e.g. memory extraction).
  // Enforced by the PreToolUse hook so an injected message cannot make a
  // silent maintenance run install tools or change settings.
  allowedTools?: string[];
  // Signalled by the PreCompact hook so the main loop can extract facts from
  // messages about to be lost. Processed once and cleared.
  pendingMemoryExtraction?: { groupFolder: string; chatId: string };
}

export function createRunState(): RunState {
  return { pendingMessages: [], pendingFiles: [], pendingSchedules: [] };
}

// Keep the newest UTF-8 content without splitting a multi-byte character.
// `String.prototype.slice(-N)` counts UTF-16 code units, so it can retain up
// to 4N bytes and exceed a byte-oriented limit.
export function truncateUtf8Tail(text: string, maxBytes: number): string {
  if (maxBytes <= 0) return '';
  const buf = Buffer.from(text, 'utf-8');
  if (buf.length <= maxBytes) return text;
  let start = buf.length - maxBytes;
  while (start < buf.length && (buf[start]! & 0xc0) === 0x80) start++;
  return buf.subarray(start).toString('utf-8');
}

// === Config ===

export interface Config {
  telegramBotToken: string;
  telegramChatId: string;
  dataDir: string;
  groupsDir: string;
}
