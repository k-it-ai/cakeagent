import type { Channel, TelegramUpdate, BotCommand, CakeSettings } from '../src/types.js';
import { closeSync, constants, fstatSync, openSync, readFileSync, unlinkSync, writeFileSync } from 'node:fs';
import { createHash } from 'node:crypto';
import { log } from '../src/logger.js';

/** Acquire a single-instance lock for the given bot token.
 * Creates a lock file at /tmp/cakeagent-<sha256(token)>.lock.
 * Returns a cleanup function that releases the lock.
 * Throws if another instance already holds the lock. */
export function acquireTelegramLock(token: string): () => void {
  const hash = createHash('sha256').update(token).digest('hex').slice(0, 32);
  const lockPath = `/tmp/cakeagent-${hash}.lock`;
  let fd: number;
  try {
    // O_EXCL | O_CREAT fails atomically if the file already exists
    fd = openSync(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
    writeFileSync(fd, `${process.pid}\n`, { encoding: 'utf-8' });
  } catch (err) {
    const e = err as NodeJS.ErrnoException;
    if (e.code === 'EEXIST') {
      // Lock exists - check if the holder is still alive
      try {
        const pidStr = readFileSync(lockPath, 'utf-8').trim();
        const pid = parseInt(pidStr, 10);
        if (!Number.isNaN(pid) && pid > 0) {
          // Send signal 0 to check if process exists
          try {
            process.kill(pid, 0);
            throw new Error(`Another CakeAgent instance is already running for this bot token (PID ${pid}).`);
          } catch {
            // Process doesn't exist - stale lock, we can take it
            unlinkSync(lockPath);
            fd = openSync(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
            writeFileSync(fd, `${process.pid}\n`, { encoding: 'utf-8' });
          }
        } else {
          // Invalid PID in lock file - stale lock
          unlinkSync(lockPath);
          fd = openSync(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
          writeFileSync(fd, `${process.pid}\n`, { encoding: 'utf-8' });
        }
      } catch (e2) {
        if (e2 instanceof Error && e2.message.includes('already running')) throw e2;
        // Any other error - treat as stale
        try { unlinkSync(lockPath); } catch { /* ignore */ }
        fd = openSync(lockPath, constants.O_CREAT | constants.O_EXCL | constants.O_WRONLY, 0o600);
        writeFileSync(fd, `${process.pid}\n`, { encoding: 'utf-8' });
      }
    } else {
      throw new Error(`Failed to acquire Telegram lock: ${e.message}`);
    }
  }
  return () => {
    try { closeSync(fd); } catch { /* ignore */ }
    try { unlinkSync(lockPath); } catch { /* ignore */ }
  };
}

function combineSignal(signal: AbortSignal | undefined, timeoutMs: number): AbortSignal {
  const timeout = AbortSignal.timeout(timeoutMs);
  return signal ? AbortSignal.any([signal, timeout]) : timeout;
}

async function tg(token: string, method: string, body?: unknown, retries = 0, signal?: AbortSignal): Promise<any> {
  const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : undefined,
    signal: combineSignal(signal, method === 'getUpdates' ? 45_000 : 30_000),
  });
  let json: { ok: boolean; result?: any; description?: string; parameters?: { retry_after?: number } };
  try {
    json = await res.json() as typeof json;
  } catch {
    throw new Error(`Telegram ${method}: invalid JSON response (HTTP ${res.status})`);
  }
  if (!json.ok) {
    if (res.status === 429 && retries < 3) {
      const wait = Math.min(Math.max(json.parameters?.retry_after ?? 5, 1), 60) * 1000;
      await new Promise(r => setTimeout(r, wait));
      return tg(token, method, body, retries + 1, signal);
    }
    throw new Error(`Telegram ${method}: ${json.description ?? `HTTP ${res.status}`}`);
  }
  return json.result;
}

async function tgForm(token: string, method: string, form: FormData, retries = 0): Promise<any> {
  const res = await fetch(`https://api.telegram.org/bot${token}/${method}`, {
    method: 'POST',
    body: form,
    signal: combineSignal(undefined, 120_000),
  });
  let json: { ok: boolean; result?: any; description?: string; parameters?: { retry_after?: number } };
  try {
    json = await res.json() as typeof json;
  } catch {
    throw new Error(`Telegram ${method}: invalid JSON response (HTTP ${res.status})`);
  }
  if (!json.ok) {
    if (res.status === 429 && retries < 3) {
      const wait = Math.min(Math.max(json.parameters?.retry_after ?? 5, 1), 60) * 1000;
      await new Promise(r => setTimeout(r, wait));
      return tgForm(token, method, form, retries + 1);
    }
    throw new Error(`Telegram ${method}: ${json.description ?? `HTTP ${res.status}`}`);
  }
  return json.result;
}

function safeCut(text: string, cut: number): number {
  // Don't split a UTF-16 surrogate pair (emoji, some CJK extensions).
  if (cut > 0 && cut < text.length) {
    const code = text.charCodeAt(cut - 1);
    if (code >= 0xD800 && code <= 0xDBFF) return cut - 1;
  }
  return cut;
}

function chunkText(text: string, maxLen = 3800): string[] {
  if (text.length <= maxLen) return [text];
  const chunks: string[] = [];
  let remaining = text;
  while (remaining.length > 0) {
    if (remaining.length <= maxLen) { chunks.push(remaining); break; }
    let cut = remaining.lastIndexOf('\n\n', maxLen);
    if (cut <= 0) cut = remaining.lastIndexOf('\n', maxLen);
    if (cut <= 0) cut = remaining.lastIndexOf(' ', maxLen);
    if (cut <= 0) cut = maxLen;
    cut = safeCut(remaining, cut);
    if (cut <= 0) cut = Math.min(maxLen, remaining.length);
    chunks.push(remaining.slice(0, cut));
    remaining = remaining.slice(cut).trimStart();
  }
  return chunks;
}

function escapeHtml(text: string): string {
  return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

function renderMarkdownText(text: string): string {
  return escapeHtml(text)
    .replace(/\*\*(.+?)\*\*/g, '<b>$1</b>')
    .replace(/\*(.+?)\*/g, '<i>$1</i>')
    .replace(/__(.+?)__/g, '<u>$1</u>')
    .replace(/~~(.+?)~~/g, '<s>$1</s>');
}

function markdownToHtml(text: string): string {
  // Tokenise fenced/inline code first, then apply markdown only to the
  // surrounding prose. This prevents ** or _ inside code from becoming HTML.
  const token = /```[^\n`]*\n?([\s\S]*?)```|`([^`\n]+)`/g;
  let out = '';
  let last = 0;
  let match: RegExpExecArray | null;
  while ((match = token.exec(text)) !== null) {
    out += renderMarkdownText(text.slice(last, match.index));
    if (match[1] !== undefined) out += `<pre>${escapeHtml(match[1].trimEnd())}</pre>`;
    else out += `<code>${escapeHtml(match[2] ?? '')}</code>`;
    last = token.lastIndex;
  }
  out += renderMarkdownText(text.slice(last));
  return out;
}

function buildSettingsKeyboard(settings: CakeSettings): any {
  const btn = (label: string, data: string) => ({ text: label, callback_data: data });
  const mark = (active: boolean, label: string) => active ? `${label} ✓` : label;
  const isModel = (m: string) => settings.model.includes(m);
  const isThink = (t: string) => settings.thinkingLevel === t;

  return {
    inline_keyboard: [
      [
        btn(mark(isModel('haiku'), 'Haiku'), 'model:claude-haiku-4-5-20251001'),
        btn(mark(isModel('sonnet'), 'Sonnet'), 'model:claude-sonnet-4-6'),
        btn(mark(isModel('opus'), 'Opus'), 'model:claude-opus-4-6'),
      ],
      [
        btn(mark(isThink('off'), 'Think: Off'), 'thinking:off'),
        btn(mark(isThink('low'), 'Low'), 'thinking:low'),
        btn(mark(isThink('medium'), 'Med'), 'thinking:medium'),
        btn(mark(isThink('high'), 'High'), 'thinking:high'),
      ],
      [
        btn(mark(settings.voiceReceive, 'Voice In'), 'voiceReceive:toggle'),
        btn(mark(settings.voiceSend, 'Voice Out'), 'voiceSend:toggle'),
      ],
      [
        btn(mark(!!settings.morningCheckinCron, 'Morning Brief'), 'morningCheckin:toggle'),
      ],
    ],
  };
}

export function createTelegramChannel(
  token: string,
  allowedChatIds: () => Set<string>,
  persistOffset?: { load: () => number; save: (offset: number) => void },
): Channel {
  let offset = persistOffset?.load() ?? 0;
  let typingInterval: ReturnType<typeof setInterval> | null = null;

  return {
    name: 'telegram',

    async *poll(signal: AbortSignal): AsyncGenerator<TelegramUpdate> {
      while (!signal.aborted) {
        try {
          const updates = await tg(token, 'getUpdates', {
            offset,
            timeout: 30,
            allowed_updates: ['message', 'callback_query'],
          }, 0, signal);

          for (const u of updates) {
            offset = u.update_id + 1;

            if (u.callback_query) {
              const cq = u.callback_query;
              const chatId = String(cq.message?.chat?.id ?? '');
              if (!allowedChatIds().has(chatId)) {
                persistOffset?.save(offset);
                continue;
              }
              yield {
                type: 'callback_query',
                callbackQuery: {
                  id: cq.id,
                  chatId,
                  messageId: cq.message?.message_id ?? 0,
                  data: cq.data ?? '',
                  senderId: String(cq.from?.id ?? ''),
                },
              };
              // Persist only after the consumer has handled the update. A crash
              // during handling replays it instead of silently losing it.
              persistOffset?.save(offset);
              continue;
            }

            if (u.message) {
              const m = u.message;
              const chatId = String(m.chat.id);
              if (!allowedChatIds().has(chatId)) {
                persistOffset?.save(offset);
                continue;
              }

              const reply = m.reply_to_message;
              yield {
                type: 'message',
                message: {
                  id: `tg_${m.message_id}_${chatId}`,
                  text: m.text ?? m.caption
                    ?? (m.photo ? '[Photo]' : null)
                    ?? (m.document ? `[Document: ${m.document.file_name ?? 'file'}]` : null)
                    ?? (m.sticker ? `[Sticker${m.sticker.emoji ? ': ' + m.sticker.emoji : ''}]` : null)
                    ?? (m.contact ? `[Contact: ${m.contact.first_name}${m.contact.last_name ? ' ' + m.contact.last_name : ''} — ${m.contact.phone_number}]` : null)
                    ?? (m.location ? `[Location: ${m.location.latitude}, ${m.location.longitude}]` : null)
                    ?? (m.poll ? `[Poll: "${m.poll.question}" — ${m.poll.options?.map((o: any) => o.text).join(', ')}]` : null)
                    ?? undefined,
                  voiceFileId: m.voice?.file_id ?? m.audio?.file_id ?? undefined,
                  photoFileId: m.photo ? m.photo[m.photo.length - 1]?.file_id : undefined,
                  documentFileId: m.document?.file_id ?? undefined,
                  documentName: m.document?.file_name ?? undefined,
                  senderId: String(m.from?.id ?? ''),
                  senderName: m.from?.first_name ?? 'Unknown',
                  chatId,
                  timestamp: m.date * 1000,
                  isGroup: m.chat.type !== 'private',
                  replyTo: reply ? {
                    text: m.quote?.text ?? reply.text ?? reply.caption,
                    senderName: reply.from?.first_name,
                  } : undefined,
                },
              };
              persistOffset?.save(offset);
            }
          }
        } catch (err) {
          if (signal.aborted) break;
          log.error({ context: 'telegram', err: (err as Error).message }, 'Poll error');
          await new Promise(r => setTimeout(r, 5000));
        }
      }
    },

    async send(chatId: string, text: string): Promise<void> {
      if (!text) return;
      for (const chunk of chunkText(text)) {
        const html = markdownToHtml(chunk);
        try {
          await tg(token, 'sendMessage', {
            chat_id: chatId,
            text: html,
            parse_mode: 'HTML',
          });
        } catch (htmlErr) {
          // Fall back to plain text for malformed HTML / unsupported markup.
          try {
            await tg(token, 'sendMessage', { chat_id: chatId, text: chunk });
          } catch (plainErr) {
            log.error({ context: 'telegram', err: (plainErr as Error).message }, 'Send failed');
            throw new Error(`Telegram send failed: ${(plainErr as Error).message}`);
          }
          log.warn({ context: 'telegram', err: (htmlErr as Error).message }, 'HTML send failed; sent as plain text');
        }
      }
    },

    async sendFile(chatId: string, filePath: string, caption?: string): Promise<void> {
      const { basename, extname } = await import('node:path');
      const maxBytes = 50 * 1024 * 1024;
      // Re-open with O_NOFOLLOW at send time. The path was validated when the
      // tool was called, but the agent can still change its own group folder
      // before queued side effects are flushed; this prevents swapping in a
      // symlink to .env between validation and upload.
      const fd = openSync(filePath, constants.O_RDONLY | constants.O_NOFOLLOW);
      let data: Buffer;
      try {
        const st = fstatSync(fd);
        if (!st.isFile()) throw new Error('Not a regular file');
        if (st.size > maxBytes) throw new Error(`File too large to send: ${st.size} bytes (max ${maxBytes})`);
        data = readFileSync(fd);
        // The file can grow between fstat() and the read (the agent owns its
        // group directory), so enforce the cap again on the bytes in hand.
        if (data.byteLength > maxBytes) throw new Error(`File too large to send: over ${maxBytes} bytes`);
      } finally {
        closeSync(fd);
      }
      const name = basename(filePath).replace(/[\r\n"\\;]/g, '_').slice(0, 200) || 'file';
      const ext = extname(filePath).toLowerCase();
      const isImage = ['.jpg', '.jpeg', '.png', '.gif', '.webp'].includes(ext);
      const form = new FormData();
      form.set('chat_id', chatId);
      const field = isImage ? 'photo' : 'document';
      form.set(field, new Blob([new Uint8Array(data)]), name);
      if (caption) form.set('caption', caption.slice(0, 1024));
      await tgForm(token, isImage ? 'sendPhoto' : 'sendDocument', form);
    },

    async sendVoice(chatId: string, audio: Buffer): Promise<void> {
      const form = new FormData();
      form.set('chat_id', chatId);
      form.set('voice', new Blob([new Uint8Array(audio)], { type: 'audio/ogg' }), 'voice.ogg');
      await tgForm(token, 'sendVoice', form);
    },

    startTyping(chatId: string): void {
      this.stopTyping();
      const send = () => tg(token, 'sendChatAction', { chat_id: chatId, action: 'typing' }).catch(() => {});
      send();
      typingInterval = setInterval(send, 4000);
    },

    stopTyping(): void {
      if (typingInterval) { clearInterval(typingInterval); typingInterval = null; }
    },

    async downloadFile(fileId: string): Promise<Buffer> {
      const MAX_FILE_SIZE = 20 * 1024 * 1024; // 20 MB — Telegram bot limit
      const file = await tg(token, 'getFile', { file_id: fileId });
      const filePath = typeof file?.file_path === 'string' ? file.file_path : '';
      if (!filePath || filePath.includes('..') || filePath.includes('\\')) {
        throw new Error('Telegram returned an invalid file path');
      }
      const encodedPath = filePath.split('/').map(encodeURIComponent).join('/');
      const url = `https://api.telegram.org/file/bot${token}/${encodedPath}`;
      const res = await fetch(url, { signal: combineSignal(undefined, 60_000) });
      if (!res.ok) throw new Error(`File download failed: HTTP ${res.status}`);
      const contentLength = Number(res.headers.get('content-length') || 0);
      if (contentLength > MAX_FILE_SIZE) throw new Error(`File too large: ${contentLength} bytes`);
      const reader = res.body?.getReader();
      if (!reader) throw new Error('Telegram file response had no body');
      const chunks: Uint8Array[] = [];
      let total = 0;
      while (true) {
        const { done, value } = await reader.read();
        if (done) break;
        if (!value) continue;
        total += value.byteLength;
        if (total > MAX_FILE_SIZE) {
          await reader.cancel();
          throw new Error(`File too large: over ${MAX_FILE_SIZE} bytes`);
        }
        chunks.push(value);
      }
      return Buffer.concat(chunks.map(c => Buffer.from(c)));
    },

    async sendSettingsKeyboard(chatId: string, settings: CakeSettings): Promise<number> {
      const result = await tg(token, 'sendMessage', {
        chat_id: chatId,
        text: `⚙️ <b>Settings</b>\nModel: <code>${settings.model}</code>\nThinking: <code>${settings.thinkingLevel}</code>`,
        parse_mode: 'HTML',
        reply_markup: buildSettingsKeyboard(settings),
      });
      return result.message_id;
    },

    async updateSettingsKeyboard(chatId: string, messageId: number, settings: CakeSettings): Promise<void> {
      await tg(token, 'editMessageText', {
        chat_id: chatId,
        message_id: messageId,
        text: `⚙️ <b>Settings</b>\nModel: <code>${settings.model}</code>\nThinking: <code>${settings.thinkingLevel}</code>`,
        parse_mode: 'HTML',
        reply_markup: buildSettingsKeyboard(settings),
      }).catch(err => log.error({ context: 'telegram', err: err.message }, 'Settings keyboard update failed'));
    },

    async answerCallback(callbackId: string, text?: string): Promise<void> {
      await tg(token, 'answerCallbackQuery', { callback_query_id: callbackId, text })
        .catch(err => log.error({ context: 'telegram', err: err.message }, 'answerCallback failed'));
    },

    async setCommands(commands: BotCommand[]): Promise<void> {
      await tg(token, 'setMyCommands', { commands }).catch(() => {});
    },
  };
}
