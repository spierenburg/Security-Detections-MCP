import { describe, it, expect, vi, beforeEach } from 'vitest';
import { promisify } from 'util';
import { setConfig, loadConfig, resetConfig } from '../../config.js';

const calls: Array<{ file: string; args: string[]; cwd?: string }> = [];

vi.mock('child_process', () => {
  const execFile: any = vi.fn();
  execFile[promisify.custom] = async (file: string, args: string[], opts: { cwd?: string }) => {
    calls.push({ file, args, cwd: opts?.cwd });
    return { stdout: 'https://github.com/org/repo/pull/1', stderr: '' };
  };
  return { execFile, exec: vi.fn() };
});

import { prStagerNode } from '../../nodes/pr-stager.js';

const baseState = (detections: any[]): any => ({
  detections,
  prs: [],
  attack_data_paths: [],
  requires_approval: false,
  approved: true,
  workflow_id: 'abcdef12-3456-7890-abcd-ef1234567890',
  errors: [],
});

describe('prStagerNode passes untrusted values as argv, never through a shell', () => {
  beforeEach(() => {
    calls.length = 0;
    resetConfig();
    const cfg = loadConfig();
    cfg.securityContentPath = '/tmp/security_content';
    cfg.dryRun = false;
    setConfig(cfg);
  });

  it('keeps shell metacharacters in file_path and name as inert single arguments', async () => {
    const evilPath = 'x.yml; touch /tmp/pwned #';
    const evilName = 'a`touch /tmp/pwned`$(id)"';
    await prStagerNode(baseState([
      { id: '1', name: evilName, technique_id: 'T1003.001', file_path: evilPath, status: 'validated' },
    ]));

    expect(calls.every(c => c.file === 'git' || c.file === 'gh')).toBe(true);
    const add = calls.find(c => c.file === 'git' && c.args[0] === 'add')!;
    expect(add.args).toEqual(['add', '--', evilPath]);
    const pr = calls.find(c => c.file === 'gh')!;
    expect(pr.args[pr.args.indexOf('--body') + 1]).toContain(evilName);
    expect(calls.every(c => c.cwd === '/tmp/security_content')).toBe(true);
  });

  it('drops detections whose technique_id is malformed before commit/PR text is built', async () => {
    const result = await prStagerNode(baseState([
      { id: '1', name: 'bad', technique_id: 'T1003"; id #', file_path: 'a.yml', status: 'validated' },
    ]));

    expect(calls).toEqual([]);
    expect(result.current_step).toBe('pr_staging_complete');
  });

  it('commits with the technique list as one -m argument', async () => {
    await prStagerNode(baseState([
      { id: '1', name: 'ok', technique_id: 'T1003.001', file_path: 'a.yml', status: 'validated' },
      { id: '2', name: 'ok2', technique_id: 'T1059', file_path: 'b.yml', status: 'validated' },
    ]));
    const commit = calls.find(c => c.file === 'git' && c.args[0] === 'commit')!;
    expect(commit.args).toEqual(['commit', '-m', 'Add automated detections for T1003.001, T1059']);
    expect(calls.find(c => c.args[0] === 'add')!.args).toEqual(['add', '--', 'a.yml', 'b.yml']);
  });
});
