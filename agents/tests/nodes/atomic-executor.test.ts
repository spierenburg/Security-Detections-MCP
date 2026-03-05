import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setConfig, loadConfig, resetConfig } from '../../config.js';

// Mock attack range tool
const mockRunAtomic = vi.fn().mockResolvedValue({ success: true, technique_id: 'T1003.001', output: 'ok', exit_code: 0 });
const mockGetStatus = vi.fn().mockResolvedValue({
  running: true,
  splunk_url: 'http://10.0.0.1:8000',
  windows_target: 'ar-win-test-0',
  target_ip: '10.0.0.2',
});
const mockDeployCustom = vi.fn().mockResolvedValue({ success: true, output: 'deployed' });
const mockWait = vi.fn().mockResolvedValue(undefined);

vi.mock('../../tools/attack-range.js', () => ({
  getAttackRangeTool: vi.fn().mockReturnValue({
    getStatus: mockGetStatus,
    runAtomicTest: mockRunAtomic,
    deployCustomAtomics: mockDeployCustom,
    waitForIngestion: mockWait,
  }),
}));

describe('atomicExecutorNode', () => {
  beforeEach(() => {
    resetConfig();
    const cfg = loadConfig();
    cfg.dryRun = false; // Disable dry-run to test real logic with mocks
    setConfig(cfg);
    vi.clearAllMocks();
    mockGetStatus.mockResolvedValue({
      running: true,
      splunk_url: 'http://10.0.0.1:8000',
      windows_target: 'ar-win-test-0',
      target_ip: '10.0.0.2',
    });
    mockRunAtomic.mockResolvedValue({ success: true, technique_id: 'T1003.001', output: 'ok', exit_code: 0 });
  });

  it('runs standard atomics for matching detections', async () => {
    const { atomicExecutorNode } = await import('../../nodes/atomic-executor.js');

    const state: any = {
      detections: [
        { id: '1', name: 'LSASS Dump Detection', technique_id: 'T1003.001', file_path: '/tmp/test.yml', status: 'draft' },
      ],
      atomic_tests: [],
      errors: [],
    };

    const result = await atomicExecutorNode(state);

    expect(result.atomic_tests).toBeDefined();
    expect(result.atomic_tests!.length).toBeGreaterThan(0);
    expect(mockRunAtomic).toHaveBeenCalledWith('T1003.001', 'ar-win-test-0');
  });

  it('returns error when Attack Range is not running', async () => {
    mockGetStatus.mockResolvedValueOnce({ running: false });

    const { atomicExecutorNode } = await import('../../nodes/atomic-executor.js');

    const state: any = {
      detections: [{ id: '1', name: 'test', technique_id: 'T1003.001', file_path: '/tmp/t.yml', status: 'draft' }],
      atomic_tests: [],
      errors: [],
    };

    const result = await atomicExecutorNode(state);
    expect(result.errors).toBeDefined();
    expect(result.errors![0]).toContain('Attack Range is not running');
  });

  it('waits for ingestion after successful tests', async () => {
    const { atomicExecutorNode } = await import('../../nodes/atomic-executor.js');

    const state: any = {
      detections: [
        { id: '1', name: 'Test Detection', technique_id: 'T1003.001', file_path: '/tmp/t.yml', status: 'draft' },
      ],
      atomic_tests: [],
      errors: [],
    };

    await atomicExecutorNode(state);
    expect(mockWait).toHaveBeenCalled();
  });
});
