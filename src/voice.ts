import { execFile } from 'node:child_process';
import { writeFileSync, readFileSync, unlinkSync, existsSync } from 'node:fs';
import { join, resolve } from 'node:path';
import { tmpdir } from 'node:os';
import { randomBytes } from 'node:crypto';
import type { CakeSettings } from './types.js';
import { DEFAULT_SETTINGS } from './types.js';
import { log } from './logger.js';

let DATA_DIR = '';
const WHISPER_LOCAL = resolve(process.env.WHISPER_CLI || 'whisper.cpp/build/bin/whisper-cli');

// Edge TTS is installed into a virtualenv under the data directory. The
// service runs with ProtectHome=true, so a ~/.local install would be visible
// to the installer but invisible to the running process.
export function edgeTtsPath(): string {
  if (process.env.EDGE_TTS_BIN) return resolve(process.env.EDGE_TTS_BIN);
  return join(DATA_DIR || resolve('data'), 'venv', 'bin', 'edge-tts');
}

export function initVoice(dataDir: string): void {
  DATA_DIR = dataDir;
}

function tmpPath(ext: string): string {
  return join(tmpdir(), `cakeagent_${randomBytes(6).toString('hex')}.${ext}`);
}

function execAsync(cmd: string, args: string[], timeout = 60_000): Promise<string> {
  return new Promise((resolve, reject) => {
    execFile(cmd, args, { timeout }, (err, stdout, stderr) => {
      if (err) reject(new Error(`${cmd} failed: ${stderr || err.message}`));
      else resolve(stdout);
    });
  });
}

export async function transcribeAudio(
  audio: Buffer,
  settings: CakeSettings,
): Promise<string | null> {
  const oggFile = tmpPath('ogg');
  const wavFile = tmpPath('wav');
  let jsonFile: string | null = null;

  try {
    writeFileSync(oggFile, audio, { mode: 0o600, flag: 'wx' });
    await execAsync('ffmpeg', ['-i', oggFile, '-ar', '16000', '-ac', '1', '-f', 'wav', '-y', wavFile]);

    const modelName = /^[a-z0-9-]{1,32}$/.test(settings.voiceSttModel) ? settings.voiceSttModel : 'base';
    const modelPath = join(DATA_DIR || resolve('data'), 'models', `ggml-${modelName}.bin`);
    if (!existsSync(modelPath)) {
      log.warn({ context: 'voice', modelPath }, 'Model not found');
      return null;
    }

    const outPrefix = wavFile.replace(/\.[^.]+$/, '');
    await execAsync(WHISPER_LOCAL, ['-m', modelPath, '-f', wavFile, '-oj', '-of', outPrefix, '-np'], 120_000);

    jsonFile = outPrefix + '.json';
    if (existsSync(jsonFile)) {
      const result = JSON.parse(readFileSync(jsonFile, 'utf-8'));
      const text = result.transcription?.map((s: any) => s.text).join(' ').trim();
      return text || null;
    }
    return null;
  } catch (err) {
    log.error({ context: 'voice', err: (err as Error).message }, 'STT failed');
    return null;
  } finally {
    for (const f of [oggFile, wavFile, ...(jsonFile ? [jsonFile] : [])]) {
      try { unlinkSync(f); } catch { /* ignore */ }
    }
  }
}

export async function synthesizeSpeech(
  text: string,
  settings: CakeSettings,
): Promise<Buffer | null> {
  const mp3File = tmpPath('mp3');
  const oggFile = tmpPath('ogg');

  try {
    const voice = settings.voiceTtsVoice || 'en-US-AriaNeural';
    const spoken = text.trim().slice(0, 4000);
    if (!spoken) return null;
    await execAsync(edgeTtsPath(), ['--voice', voice, '--text', spoken, '--write-media', mp3File]);

    if (!existsSync(mp3File)) {
      log.warn({ context: 'voice' }, 'edge-tts produced no output');
      return null;
    }

    await execAsync('ffmpeg', ['-i', mp3File, '-c:a', 'libopus', '-b:a', '48k', '-y', oggFile]);
    if (!existsSync(oggFile)) {
      log.warn({ context: 'voice' }, 'ffmpeg did not produce an OGG file');
      return null;
    }
    return readFileSync(oggFile);
  } catch (err) {
    log.error({ context: 'voice', err: (err as Error).message }, 'TTS failed');
    return null;
  } finally {
    for (const f of [mp3File, oggFile]) {
      try { unlinkSync(f); } catch { /* ignore */ }
    }
  }
}

export async function checkVoiceDeps(
  settings: CakeSettings = DEFAULT_SETTINGS,
): Promise<{ stt: boolean; tts: boolean; missing: string[] }> {
  const missing: string[] = [];
  const modelName = /^[a-z0-9-]{1,32}$/.test(settings.voiceSttModel) ? settings.voiceSttModel : 'base';
  const modelPath = join(DATA_DIR || resolve('data'), 'models', `ggml-${modelName}.bin`);

  const whisper = existsSync(WHISPER_LOCAL);
  const model = existsSync(modelPath);
  let ffmpeg = false;
  try {
    await execAsync('ffmpeg', ['-version'], 10_000);
    ffmpeg = true;
  } catch { missing.push('ffmpeg (required for audio conversion)'); }

  const stt = whisper && model && ffmpeg;
  if (!whisper) missing.push('whisper-cli (install whisper.cpp for STT)');
  if (!model) missing.push(`whisper model ggml-${modelName}.bin`);

  const edgeTts = edgeTtsPath();
  const tts = existsSync(edgeTts) && ffmpeg;
  if (!existsSync(edgeTts)) missing.push('edge-tts (run voice setup from /settings)');

  return { stt, tts, missing };
}
