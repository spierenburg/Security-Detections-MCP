import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setConfig, loadConfig, resetConfig } from '../../config.js';

// Mock MCP client for Splunk calls
const mockCallTool = vi.fn();
vi.mock('../../tools/mcp-client.js', () => ({
  getMCPClient: vi.fn().mockReturnValue({ callTool: mockCallTool }),
}));

describe('splunkValidatorNode', () => {
  beforeEach(() => {
    resetConfig();
    const cfg = loadConfig();
    cfg.dryRun = false; // Disable dry-run to test real logic with mocks
    setConfig(cfg);
    vi.clearAllMocks();
  });

  it('marks detection as validated when events are found', async () => {
    mockCallTool.mockResolvedValue({
      success: true,
      result: { results: [{ _raw: 'event1' }, { _raw: 'event2' }] },
    });

    const { splunkValidatorNode } = await import('../../nodes/splunk-validator.js');

    const state: any = {
      detections: [
        { id: 'd1', name: 'Test Detection', technique_id: 'T1003.001', file_path: '/tmp/t.yml', status: 'draft' },
      ],
      atomic_tests: [
        { technique_id: 'T1003.001', test_name: 'test', execution_status: 'completed' },
      ],
      errors: [],
    };

    const result = await splunkValidatorNode(state);
    const det = result.detections!.find((d: any) => d.id === 'd1');
    expect(det).toBeDefined();
    expect(det!.status).toBe('validated');
    expect(det!.validation_result!.event_count).toBe(2);
  });

  it('marks detection as failed when no events match', async () => {
    // run_detection returns 0 results
    mockCallTool.mockResolvedValue({
      success: true,
      result: { _mcp_pending: true },
    });

    const { splunkValidatorNode } = await import('../../nodes/splunk-validator.js');

    const state: any = {
      detections: [
        { id: 'd2', name: 'Failing Detection', technique_id: 'T1059.001', file_path: '/tmp/f.yml', status: 'draft' },
      ],
      atomic_tests: [
        { technique_id: 'T1059.001', test_name: 'test', execution_status: 'completed' },
      ],
      errors: [],
    };

    const result = await splunkValidatorNode(state);
    const det = result.detections!.find((d: any) => d.id === 'd2');
    expect(det).toBeDefined();
    expect(det!.status).toBe('failed');
  });

  it('skips detections without completed atomic tests', async () => {
    const { splunkValidatorNode } = await import('../../nodes/splunk-validator.js');

    const state: any = {
      detections: [
        { id: 'd3', name: 'No Atomic', technique_id: 'T1234', file_path: '/tmp/n.yml', status: 'draft' },
      ],
      atomic_tests: [
        { technique_id: 'T1234', test_name: 'test', execution_status: 'failed' },
      ],
      errors: [],
    };

    const result = await splunkValidatorNode(state);
    expect(result.current_step).toBe('splunk_validation_complete');
  });
});
