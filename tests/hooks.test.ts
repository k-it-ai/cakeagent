import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import { mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { initDb, closeDb } from '../src/store.js';
import { createHooks } from '../src/hooks.js';
import { createRunState } from '../src/types.js';
import type { HookInput } from '@anthropic-ai/claude-agent-sdk';

let tmp: string;
before(() => {
  tmp = mkdtempSync(join(tmpdir(), 'cakeagent-hooks-'));
  initDb(tmp);
});
after(() => {
  closeDb();
  rmSync(tmp, { recursive: true, force: true });
});

async function runBash(groupFolder: string, command: string) {
  const state = createRunState();
  state.currentGroupFolder = groupFolder;
  const hooks = createHooks(state, join(tmp, 'groups'), join(tmp, 'data'));
  const matcher = hooks.PreToolUse.find(h => h.matcher === '^Bash$');
  assert.ok(matcher);
  const hook = matcher.hooks[0];
  assert.ok(hook);
  return hook({
    hook_event_name: 'PreToolUse',
    tool_name: 'Bash',
    tool_input: { command },
    session_id: 'test',
    transcript_path: '',
    cwd: join(tmp, 'groups', groupFolder),
  } as unknown as HookInput);
}

test('hooks: groups cannot use Bash, main can', async () => {
  const group = await runBash('family', 'ls') as any;
  assert.equal(group.hookSpecificOutput?.permissionDecision, 'deny');
  const main = await runBash('main', 'ls') as any;
  assert.equal(main.hookSpecificOutput?.permissionDecision, 'allow');
});

test('hooks: groups cannot smuggle sudo through a script command', async () => {
  const res = await runBash('family', 'bash script.sh') as any;
  assert.equal(res.hookSpecificOutput?.permissionDecision, 'deny');
});
