import { existsSync, readFileSync } from 'fs';
import { resolve, isAbsolute } from 'path';
import yaml from 'js-yaml';
import { getConfig } from '../config.js';
import type { PipelineState } from '../state/types.js';

const REQUIRED_YAML_FIELDS = ['name', 'id', 'search', 'description'] as const;
const MITRE_PATH = ['tags', 'mitre_attack_id'];

export async function verifierNode(state: PipelineState): Promise<Partial<PipelineState>> {
  console.log('[Verifier] Running verification checks...');

  const cfg = getConfig();

  if (cfg.dryRun) {
    console.log('[Verifier] Dry-run mode - returning mock VERIFIED');
    return {
      current_step: 'verification_complete',
      warnings: [...(state.warnings ?? []), 'Dry-run mode: verification skipped'],
    };
  }

  const issues: string[] = [];

  for (const detection of state.detections) {
    const fullPath = isAbsolute(detection.file_path)
      ? detection.file_path
      : resolve(cfg.securityContentPath, detection.file_path);

    if (!existsSync(fullPath)) {
      issues.push(`Detection file missing: ${detection.file_path}`);
      continue;
    }

    let parsed: unknown;
    try {
      const content = readFileSync(fullPath, 'utf-8');
      parsed = yaml.load(content);
    } catch (err) {
      issues.push(`YAML parse error in ${detection.file_path}: ${err instanceof Error ? err.message : String(err)}`);
      continue;
    }

    if (!parsed || typeof parsed !== 'object') {
      issues.push(`Invalid YAML structure in ${detection.file_path}`);
      continue;
    }

    const obj = parsed as Record<string, unknown>;
    for (const field of REQUIRED_YAML_FIELDS) {
      if (obj[field] === undefined || obj[field] === null || obj[field] === '') {
        issues.push(`Missing required field "${field}" in ${detection.file_path}`);
      }
    }

    let mitre = obj;
    for (const key of MITRE_PATH) {
      mitre = (mitre as Record<string, unknown>)?.[key] as Record<string, unknown>;
      if (mitre === undefined) break;
    }
    const mitreVal = Array.isArray(mitre) ? mitre : mitre;
    if (!mitreVal || !Array.isArray(mitreVal) || mitreVal.length === 0) {
      issues.push(`Missing or empty tags.mitre_attack_id in ${detection.file_path}`);
    }
  }

  const techniquesWithAtomics = new Set(state.atomic_tests.map((t) => t.technique_id));
  const techniquesWithDetections = new Set(state.detections.map((d) => d.technique_id));

  for (const tid of techniquesWithDetections) {
    if (!techniquesWithAtomics.has(tid)) {
      issues.push(`No atomic test for technique ${tid} (detection exists but no test ran or was skipped)`);
    }
  }

  for (const test of state.atomic_tests) {
    if (test.execution_status === 'pending' || test.execution_status === 'running') {
      issues.push(`Atomic test ${test.test_name} (${test.technique_id}) still ${test.execution_status}`);
    }
  }

  for (const detection of state.detections) {
    if (!detection.validation_result) {
      issues.push(`No validation result for detection ${detection.name} (${detection.file_path})`);
    }
  }

  for (const pr of state.prs ?? []) {
    if (pr.status === 'merged') {
      issues.push(`PR ${pr.repo} #${pr.number ?? '?'} is merged - should remain DRAFT`);
    }
    if (pr.is_draft === false && pr.status !== 'staged') {
      issues.push(`PR ${pr.repo} #${pr.number ?? '?'} is not DRAFT`);
    }
  }

  const verified = issues.length === 0;

  if (verified) {
    console.log('[Verifier] VERIFIED - all checks passed');
    return {
      current_step: 'verification_complete',
    };
  }

  console.log('[Verifier] FAILED - issues found:');
  issues.forEach((i) => console.log(`  - ${i}`));

  return {
    current_step: 'verification_failed',
    errors: [...(state.errors ?? []), ...issues],
  };
}
