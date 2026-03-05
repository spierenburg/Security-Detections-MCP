import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setConfig, loadConfig, resetConfig } from '../../config.js';

// Mock the MCP client
vi.mock('../../tools/mcp-client.js', () => ({
  getMCPClient: vi.fn().mockReturnValue({
    callTool: vi.fn().mockImplementation(async (call: any) => {
      // T1003.001 has no coverage, T1059.001 has one detection
      if (call.arguments.technique_id === 'T1003.001') {
        return { success: true, result: [] };
      }
      if (call.arguments.technique_id === 'T1059.001') {
        return { success: true, result: [{ id: 'existing-1', name: 'PowerShell Detection' }] };
      }
      return { success: true, result: [] };
    }),
  }),
}));

describe('coverageAnalyzerNode', () => {
  beforeEach(() => {
    resetConfig();
    const cfg = loadConfig();
    cfg.dryRun = true;
    setConfig(cfg);
  });

  it('identifies gaps when no coverage exists', async () => {
    const { coverageAnalyzerNode } = await import('../../nodes/coverage-analyzer.js');

    const state: any = {
      techniques: [
        { id: 'T1003.001', name: 'LSASS Memory', tactic: 'Credential Access', confidence: 0.9, context: 'test' },
      ],
      gaps: [],
      errors: [],
    };

    const result = await coverageAnalyzerNode(state);
    expect(result.gaps).toBeDefined();
    expect(result.gaps!.length).toBe(1);
    expect(result.gaps![0].technique_id).toBe('T1003.001');
    expect(result.gaps![0].priority).toBe('high');
  });

  it('flags medium priority for single-coverage high-confidence technique', async () => {
    const { coverageAnalyzerNode } = await import('../../nodes/coverage-analyzer.js');

    const state: any = {
      techniques: [
        { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', confidence: 0.9, context: 'test' },
      ],
      gaps: [],
      errors: [],
    };

    const result = await coverageAnalyzerNode(state);
    expect(result.gaps!.length).toBe(1);
    expect(result.gaps![0].priority).toBe('medium');
  });

  it('returns no gaps when full coverage exists', async () => {
    const { getMCPClient } = await import('../../tools/mcp-client.js');
    (getMCPClient as any).mockReturnValueOnce({
      callTool: vi.fn().mockResolvedValue({
        success: true,
        result: [{ id: '1' }, { id: '2' }],
      }),
    });

    const { coverageAnalyzerNode } = await import('../../nodes/coverage-analyzer.js');

    const state: any = {
      techniques: [
        { id: 'T1059.001', name: 'PowerShell', tactic: 'Execution', confidence: 0.5, context: '' },
      ],
      gaps: [],
      errors: [],
    };

    const result = await coverageAnalyzerNode(state);
    // low confidence + 2 detections = no gap
    expect(result.gaps!.length).toBe(0);
  });
});
