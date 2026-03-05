import { describe, it, expect, beforeAll } from 'vitest';
import { setConfig, loadConfig, resetConfig } from '../../config.js';
import { createInitialState, createDetectionPipeline } from '../../graphs/detection-pipeline.js';

describe('E2E dry-run pipeline', () => {
  beforeAll(() => {
    resetConfig();
    const cfg = loadConfig();
    cfg.dryRun = true;
    cfg.anthropicApiKey = 'dry-run-test';
    setConfig(cfg);
  });

  it('createDetectionPipeline compiles in dry-run mode', () => {
    const pipeline = createDetectionPipeline();
    expect(pipeline).toBeDefined();
  });

  it('initial state is valid for all input types', () => {
    const types = ['threat_report', 'technique', 'cisa_alert', 'manual'] as const;
    for (const t of types) {
      const state = createInitialState(t, 'test content');
      expect(state.input_type).toBe(t);
      expect(state.workflow_id).toBeDefined();
    }
  });
});
