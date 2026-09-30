import { describe, it, expect, vi, beforeEach } from 'vitest';
import { setConfig, loadConfig, resetConfig } from '../../config.js';

// withStructuredOutput resolves to the already-parsed object, not raw message text.
const MOCK_LLM_RESPONSE = {
  techniques: [
    {
      id: 'T1003.001',
      name: 'LSASS Memory',
      tactic: 'Credential Access',
      confidence: 0.95,
      context: 'Report describes using procdump to dump LSASS',
    },
    {
      id: 'T1059.001',
      name: 'PowerShell',
      tactic: 'Execution',
      confidence: 0.8,
      context: 'PowerShell used for download cradle',
    },
  ],
};

const mockInvoke = vi.fn().mockResolvedValue(MOCK_LLM_RESPONSE);
let capturedSchema: any;

vi.mock('@langchain/anthropic', () => ({
  ChatAnthropic: vi.fn().mockImplementation(() => ({
    withStructuredOutput: (schema: unknown) => {
      capturedSchema = schema;
      return { invoke: mockInvoke };
    },
  })),
}));

// Static import so the mock is resolved before the module loads
import { ctiAnalystNode } from '../../nodes/cti-analyst.js';

describe('ctiAnalystNode', () => {
  beforeEach(() => {
    resetConfig();
    const cfg = loadConfig();
    cfg.anthropicApiKey = 'test-key';
    setConfig(cfg);
    mockInvoke.mockResolvedValue(MOCK_LLM_RESPONSE);
  });

  it('extracts techniques from threat intel', async () => {
    const state: any = {
      input_type: 'threat_report',
      input_content: 'APT group used procdump to dump LSASS memory and PowerShell download cradle.',
      techniques: [],
      gaps: [],
      detections: [],
      atomic_tests: [],
      attack_data_paths: [],
      prs: [],
      errors: [],
      warnings: [],
    };

    const result = await ctiAnalystNode(state);

    expect(result.techniques).toBeDefined();
    expect(result.techniques!.length).toBe(2);
    expect(result.techniques![0].id).toBe('T1003.001');
    expect(result.techniques![1].id).toBe('T1059.001');
    expect(result.current_step).toBe('cti_analysis_complete');
  });

  it('handles empty LLM response gracefully', async () => {
    mockInvoke.mockResolvedValueOnce({ techniques: [] });

    const state: any = {
      input_content: 'Nothing interesting here.',
      techniques: [],
      errors: [],
    };

    const result = await ctiAnalystNode(state);
    expect(result.techniques).toEqual([]);
    expect(result.current_step).toBe('cti_analysis_complete');
    expect(result.errors).toBeUndefined();
  });

  it('handles LLM error gracefully', async () => {
    mockInvoke.mockRejectedValueOnce(new Error('API rate limit'));

    const state: any = {
      input_content: 'test content',
      techniques: [],
      errors: [],
    };

    const result = await ctiAnalystNode(state);
    expect(result.techniques).toEqual([]);
    expect(result.errors).toBeDefined();
    expect(result.errors![0]).toContain('rate limit');
  });

  it('post-parse filter drops malformed IDs if schema validation is bypassed', async () => {
    const t = (id: string) => ({ id, name: 'n', tactic: 't', confidence: 0.5, context: 'c' });
    mockInvoke.mockResolvedValueOnce({
      techniques: [t('T1003.001'), t('../../../evil'), t('T1059.1'), t('T1059')],
    });

    const state: any = { input_content: 'x', techniques: [], errors: [] };
    const result = await ctiAnalystNode(state);

    expect(result.techniques!.map(x => x.id)).toEqual(['T1003.001', 'T1059']);
    expect(result.current_step).toBe('cti_analysis_complete');
  });

  // The real parser runs this schema and throws on failure, so in production one
  // malformed ID fails the whole batch (cti_analysis_failed); the mock resolves past it.
  it('schema rejects path-traversal and malformed technique IDs', async () => {
    await ctiAnalystNode({ input_content: 'x', techniques: [], errors: [] } as any);
    const t = (id: string) => ({ techniques: [{ id, name: 'n', tactic: 't', confidence: 0.5, context: 'c' }] });

    expect(capturedSchema.safeParse(t('T1003.001')).success).toBe(true);
    expect(capturedSchema.safeParse(t('../../../evil')).success).toBe(false);
    expect(capturedSchema.safeParse(t('T1059.1')).success).toBe(false);
    expect(capturedSchema.safeParse(t('T1003\n')).success).toBe(false);
  });
});
