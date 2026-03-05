import { getConfig } from '../config.js';
import type { PipelineState, Detection } from '../state/types.js';
import { splunkValidatorNode } from './splunk-validator.js';

export async function siemValidatorNode(state: PipelineState): Promise<Partial<PipelineState>> {
  const cfg = getConfig();
  const platform = cfg.siemPlatform ?? 'splunk';

  console.log(`[SIEM Validator] Platform: ${platform}, dry-run: ${cfg.dryRun}`);

  if (cfg.dryRun) {
    console.log('[SIEM Validator] Dry-run mode - returning mock validation results');
    const mockDetections = state.detections.map((d) => ({
      ...d,
      status: 'validated' as const,
      validation_result: {
        passed: true,
        event_count: 5,
      },
    }));
    console.log(`[SIEM Validator] Mock validated ${mockDetections.length} detection(s)`);
    return {
      detections: mockDetections,
      current_step: 'siem_validation_complete',
      warnings: ['Dry-run mode: no actual SIEM validation performed'],
    };
  }

  switch (platform) {
    case 'splunk': {
      return splunkValidatorNode(state);
    }
    case 'sentinel': {
      console.log('[SIEM Validator] Sentinel: Azure CLI KQL validation would run against workspace');
      return handleNonSplunkPlatform(state, 'sentinel');
    }
    case 'elastic': {
      console.log('[SIEM Validator] Elastic: Elasticsearch API EQL/ES|QL validation would run');
      return handleNonSplunkPlatform(state, 'elastic');
    }
    case 'sigma': {
      console.log('[SIEM Validator] Sigma: pySigma convert + validate would run');
      return handleNonSplunkPlatform(state, 'sigma');
    }
    default: {
      console.log(`[SIEM Validator] Unknown platform "${platform}", defaulting to draft`);
      return handleNonSplunkPlatform(state, platform);
    }
  }
}

function handleNonSplunkPlatform(
  state: PipelineState,
  platform: string
): Partial<PipelineState> {
  const completedAtomics = new Set(
    state.atomic_tests
      .filter((t) => t.execution_status === 'completed')
      .map((t) => t.technique_id)
  );

  const detectionsToUpdate = state.detections.filter(
    (d) => completedAtomics.has(d.technique_id) && d.status === 'draft'
  );

  const updatedDetections: Detection[] = state.detections.map((d) => {
    const needsUpdate = detectionsToUpdate.some((u) => u.id === d.id);
    if (!needsUpdate) return d;
    return {
      ...d,
      status: 'draft' as const,
      validation_result: {
        passed: false,
        event_count: 0,
        error: `Manual ${platform} validation required - automated validation not implemented`,
      },
    };
  });

  const warning = `Platform ${platform}: detections marked as draft - manual validation needed`;
  console.log(`[SIEM Validator] ${warning}`);

  return {
    detections: updatedDetections,
    current_step: 'siem_validation_complete',
    warnings: [...(state.warnings ?? []), warning],
  };
}
