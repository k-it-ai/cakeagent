import { query } from '@anthropic-ai/claude-agent-sdk';
import type { HookCallbackMatcher } from '@anthropic-ai/claude-agent-sdk';
import { readFileSync, existsSync, lstatSync } from 'node:fs';
import { resolve } from 'node:path';
import { isPathInside } from './security.js';
import type { AgentRunParams, CakeSettings } from './types.js';
import { log } from './logger.js';

const MCP_JSON_PATH = resolve('.mcp.json');

// The Claude subprocess and any MCP servers it spawns do not need the bot
// token or other application secrets. Passing a filtered environment keeps
// those values out of prompt-injected `printenv`/MCP exfiltration attempts
// while retaining everything the CLI needs to authenticate and run locally.
function childEnv(): Record<string, string | undefined> {
  const exact = new Set([
    'PATH', 'HOME', 'USER', 'LOGNAME', 'SHELL', 'PWD', 'TERM', 'LANG', 'LANGUAGE', 'TZ',
    'TMPDIR', 'TMP', 'TEMP', 'NO_COLOR', 'FORCE_COLOR',
    'HTTP_PROXY', 'HTTPS_PROXY', 'NO_PROXY', 'http_proxy', 'https_proxy', 'no_proxy',
    'SSL_CERT_FILE', 'SSL_CERT_DIR', 'NODE_EXTRA_CA_CERTS',
  ]);
  const out: Record<string, string | undefined> = {};
  for (const [key, value] of Object.entries(process.env)) {
    if (value === undefined) continue;
    if (exact.has(key) || key.startsWith('ANTHROPIC_') || key.startsWith('CLAUDE_') ||
        key.startsWith('LC_') || key.startsWith('XDG_')) {
      out[key] = value;
    }
  }
  out.CLAUDE_AGENT_SDK_CLIENT_APP = 'cakeagent';
  // Claude Code otherwise preserves `cd` inside the project between Bash
  // calls. Our hooks resolve relative paths against the group directory, so a
  // persisted subdirectory cwd would let relative writes bypass that policy.
  out.CLAUDE_BASH_MAINTAIN_PROJECT_WORKING_DIR = '1';
  return out;
}

interface AgentDeps {
  picoServer: ReturnType<typeof import('@anthropic-ai/claude-agent-sdk').createSdkMcpServer>;
  hooks: Record<string, HookCallbackMatcher[]>;
  settings: CakeSettings;
  groupsDir: string;
  // Optional allowlist for constrained maintenance runs. The hook layer also
  // enforces this via RunState.allowedTools.
  allowedTools?: string[];
}

export async function runAgent(
  params: AgentRunParams,
  deps: AgentDeps,
  onText?: (text: string) => Promise<void>,
): Promise<{ sessionId: string; result: string }> {
  if (!/^[a-zA-Z0-9_-]{1,50}$/.test(params.groupFolder)) {
    throw new Error('Invalid group folder');
  }
  const groupPath = resolve(deps.groupsDir, params.groupFolder);
  if (!isPathInside(resolve(deps.groupsDir), groupPath)) throw new Error('Group folder escapes groups directory');

  let externalMcp: Record<string, unknown> = {};
  if (existsSync(MCP_JSON_PATH)) {
    try {
      if (lstatSync(MCP_JSON_PATH).isSymbolicLink()) {
        throw new Error('.mcp.json is a symlink');
      }
      const raw = JSON.parse(readFileSync(MCP_JSON_PATH, 'utf-8'));
      if (raw?.mcpServers && typeof raw.mcpServers === 'object' && !Array.isArray(raw.mcpServers)) {
        externalMcp = raw.mcpServers;
      }
    } catch (err) {
      log.error({ context: 'agent', err: (err as Error).message }, '.mcp.json is corrupt — starting without external MCP servers');
    }
  }
  // Constrained maintenance runs do not need third-party MCP servers and must
  // not spawn them. Apart from reducing attack surface, this avoids a server
  // doing work even though its tools are denied by the hook allowlist.
  if (deps.allowedTools) externalMcp = {};
  // The in-process server must win if a config tries to shadow it.
  delete externalMcp.cakeagent;

  let sessionId = params.sessionId ?? '';
  let result = '';
  let lastStreamedText = '';
  let timedOut = false;

  const controller = new AbortController();
  const timeout = setTimeout(() => { timedOut = true; controller.abort(); }, deps.settings.agentTimeoutMs);

  try {
    for await (const message of query({
      prompt: params.prompt,
      options: {
        cwd: groupPath,
        resume: params.sessionId || undefined,
        model: deps.settings.model || undefined,
        thinking: deps.settings.thinkingLevel === 'off'
          ? { type: 'disabled' as const }
          : { type: 'adaptive' as const },
        effort: deps.settings.thinkingLevel === 'off' ? undefined
          : (deps.settings.thinkingLevel as 'low' | 'medium' | 'high'),
        permissionMode: 'acceptEdits',
        allowedTools: deps.allowedTools ?? (params.groupFolder === 'main'
          ? [
            'Read', 'Write', 'Edit', 'Bash', 'Glob', 'Grep',
            'WebSearch',
            'Agent',
            'mcp__cakeagent__*',
          ]
          : [
            // Group chats do not get a shell or subagents (which could inherit
            // one). They can still read/write their own files and use MCP tools.
            'Read', 'Write', 'Edit', 'Glob', 'Grep',
            'WebSearch',
            'mcp__cakeagent__*',
          ]),
        agents: {
          worker: {
            description: 'General-purpose worker for complex subtasks. Use when a task benefits from isolated context — research, multi-step file operations, or any work that would clutter the main conversation.',
            prompt: 'You are a worker agent for a personal AI assistant. Complete the assigned task thoroughly and return concise results. You have the same tools as the main agent.',
          },
        },
        settingSources: ['project'],
        maxTurns: 25,
        mcpServers: {
          ...externalMcp,
          cakeagent: deps.picoServer,
        } as Record<string, any>,
        hooks: deps.hooks,
        abortController: controller,
        env: childEnv(),
      },
    })) {
      // Explicit casts avoid expensive narrowing on SDKMessage's 20+ type union.
      // Fields are verified against sdk.d.ts: SDKSystemMessage, SDKAssistantMessage, SDKResultSuccess/Error.
      const msg = message as { type: string; subtype?: string; session_id?: string;
        message?: { content?: Array<{ type: string; text?: string }> };
        result?: string; errors?: string[] };

      if (msg.type === 'system' && msg.subtype === 'init') {
        sessionId = msg.session_id ?? sessionId;
      }

      if (msg.type === 'assistant' && onText && Array.isArray(msg.message?.content)) {
        for (const block of msg.message!.content!) {
          if (block.type === 'text' && block.text) {
            const text = block.text.trim();
            if (text && text !== lastStreamedText) {
              await onText(text);
              lastStreamedText = text;
            }
          }
        }
      }

      if (msg.type === 'result') {
        if (msg.subtype === 'success') {
          result = msg.result ?? '';
        } else {
          result = msg.errors?.[0] ?? `Agent stopped: ${msg.subtype}`;
        }
      }
    }
  } catch (err) {
    // If streaming/delivery failed (or any consumer error escaped), make sure
    // the SDK subprocess is torn down rather than left running unsupervised.
    controller.abort();
    if (timedOut) {
      throw new Error(`Agent timed out after ${Math.round(deps.settings.agentTimeoutMs / 1000)}s`);
    }
    throw err;
  } finally {
    clearTimeout(timeout);
  }

  return { sessionId, result };
}
