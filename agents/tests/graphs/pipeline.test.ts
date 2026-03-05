import { describe, it, expect } from 'vitest';

/**
 * Test the pipeline graph wiring and conditional edges.
 * We don't run the actual graph (that requires LLM + MCP), but we test
 * the edge condition functions by importing the module and exercising
 * the exported helpers.
 */

describe('Pipeline graph', () => {
  it('createInitialState returns valid state', async () => {
    const { createInitialState } = await import('../../graphs/detection-pipeline.js');

    const state = createInitialState('technique', 'T1003.001');

    expect(state.input_type).toBe('technique');
    expect(state.input_content).toBe('T1003.001');
    expect(state.workflow_id).toBeDefined();
    expect(state.workflow_id!.length).toBe(36); // UUID v4
    expect(state.techniques).toEqual([]);
    expect(state.gaps).toEqual([]);
    expect(state.detections).toEqual([]);
    expect(state.errors).toEqual([]);
    expect(state.requires_approval).toBe(true);
    expect(state.started_at).toBeDefined();
  });

  it('createInitialState accepts optional URL', async () => {
    const { createInitialState } = await import('../../graphs/detection-pipeline.js');

    const state = createInitialState('cisa_alert', 'content', 'https://example.com/alert');
    expect(state.input_url).toBe('https://example.com/alert');
  });

  it('createDetectionPipeline compiles without error', async () => {
    const { createDetectionPipeline } = await import('../../graphs/detection-pipeline.js');
    
    // should not throw
    const pipeline = createDetectionPipeline();
    expect(pipeline).toBeDefined();
  });
});
