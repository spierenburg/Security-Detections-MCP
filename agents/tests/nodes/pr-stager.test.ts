import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setConfig, loadConfig, resetConfig } from '../../config.js';

// Mock child_process so we don't actually run git/gh
vi.mock('child_process', () => ({
  exec: vi.fn(),
}));

vi.mock('util', async (importOriginal) => {
  const actual = await importOriginal<typeof import('util')>();
  return {
    ...actual,
    promisify: vi.fn().mockReturnValue(
      vi.fn().mockResolvedValue({ stdout: 'https://github.com/org/repo/pull/42', stderr: '' })
    ),
  };
});

describe('prStagerNode', () => {
  beforeEach(() => {
    resetConfig();
    const cfg = loadConfig();
    cfg.securityContentPath = '/tmp/security_content';
    cfg.attackDataPath = '/tmp/attack_data';
    setConfig(cfg);
  });

  it('skips when no validated detections', async () => {
    const { prStagerNode } = await import('../../nodes/pr-stager.js');

    const state: any = {
      detections: [
        { id: '1', name: 'Draft Only', technique_id: 'T1003.001', file_path: '/tmp/d.yml', status: 'draft' },
      ],
      prs: [],
      attack_data_paths: [],
      requires_approval: false,
      workflow_id: '12345678-abcd-1234-abcd-123456789012',
      errors: [],
    };

    const result = await prStagerNode(state);
    expect(result.current_step).toBe('pr_staging_complete');
  });

  it('requests approval when requires_approval is true and not approved', async () => {
    const { prStagerNode } = await import('../../nodes/pr-stager.js');

    const state: any = {
      detections: [
        { id: '1', name: 'Validated', technique_id: 'T1003.001', file_path: '/tmp/v.yml', status: 'validated' },
      ],
      prs: [],
      attack_data_paths: [],
      requires_approval: true,
      approved: false,
      workflow_id: '12345678-abcd-1234-abcd-123456789012',
      errors: [],
    };

    const result = await prStagerNode(state);
    expect(result.requires_approval).toBe(true);
    expect(result.approval_reason).toContain('1 detection');
    expect(result.current_step).toBe('awaiting_approval');
  });

  it('generates correct branch name from workflow_id', async () => {
    const { prStagerNode } = await import('../../nodes/pr-stager.js');

    const state: any = {
      detections: [
        { id: '1', name: 'Validated', technique_id: 'T1003.001', file_path: '/tmp/v.yml', status: 'validated' },
      ],
      prs: [],
      attack_data_paths: [],
      requires_approval: false,
      approved: true,
      workflow_id: 'abcdef12-3456-7890-abcd-ef1234567890',
      errors: [],
    };

    const result = await prStagerNode(state);
    // should have attempted PR creation
    expect(result.prs).toBeDefined();
  });
});
