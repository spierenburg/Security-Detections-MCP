import { ChatAnthropic } from '@langchain/anthropic';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import yaml from 'js-yaml';
import { getConfig } from '../config.js';
import type { PipelineState, Detection } from '../state/types.js';
import { z } from 'zod';

const QAReviewSchema = z.object({
  overall_status: z.enum(['pass', 'fail', 'needs_improvement']).describe('QA verdict'),
  issues: z.array(z.string()).describe('Specific issues found'),
  summary: z.string().describe('Brief quality summary'),
});

const QAReviewResponseSchema = z.object({
  reviews: z.array(QAReviewSchema).describe('One review per detection'),
});

function loadDetectionYaml(filePath: string): Record<string, unknown> | null {
  const resolved = resolve(filePath);
  if (!existsSync(resolved)) {
    return null;
  }
  try {
    const content = readFileSync(resolved, 'utf-8');
    return yaml.load(content) as Record<string, unknown>;
  } catch {
    return null;
  }
}

function programmaticChecks(doc: Record<string, unknown>, detectionName: string): string[] {
  const issues: string[] = [];
  const nameSnake = detectionName.toLowerCase().replace(/\s+/g, '_').replace(/[^a-z0-9_]/g, '');

  const mitreIds = doc.tags && typeof doc.tags === 'object' && 'mitre_attack_id' in doc.tags
    ? (doc.tags as Record<string, unknown>).mitre_attack_id
    : null;
  if (!Array.isArray(mitreIds) || mitreIds.length === 0) {
    issues.push('Missing or invalid MITRE ATT&CK mapping (mitre_attack_id)');
  } else {
    const valid = mitreIds.every((id: unknown) =>
      typeof id === 'string' && /^T\d{4}(\.\d{3})?$/i.test(id)
    );
    if (!valid) {
      issues.push('MITRE technique IDs must follow T1234 or T1234.001 format');
    }
  }

  const desc = doc.description;
  if (typeof desc !== 'string' || desc.length < 80) {
    issues.push('Description should be substantive (80+ chars), not generic');
  }

  const kfp = doc.known_false_positives;
  if (kfp === undefined || kfp === null || (typeof kfp === 'string' && kfp.trim().length === 0)) {
    issues.push('Missing known_false_positives');
  }

  const hti = doc.how_to_implement;
  if (hti === undefined || hti === null || (typeof hti === 'string' && hti.trim().length === 0)) {
    issues.push('Missing how_to_implement');
  }

  const tests = doc.tests;
  if (!Array.isArray(tests) || tests.length === 0) {
    issues.push('Missing test data reference (tests.attack_data)');
  } else {
    const hasAttackData = tests.some((t: unknown) =>
      t && typeof t === 'object' && 'attack_data' in (t as object)
    );
    if (!hasAttackData) {
      issues.push('Tests section should include attack_data');
    }
  }

  const search = doc.search;
  if (typeof search === 'string') {
    const expectedFilter = `${nameSnake}_filter`;
    if (!search.includes(expectedFilter) && !search.includes('`' + expectedFilter + '`')) {
      issues.push(`Filter macro should follow pattern: ${expectedFilter}`);
    }
    const dmFields = ['Endpoint.Processes', 'Endpoint.Filesystem', 'Network_Traffic', 'Authentication'];
    const hasDm = dmFields.some(dm => search.includes(`datamodel=${dm}`) || search.includes(`from datamodel=${dm}`));
    if (!hasDm && !search.includes('datamodel=')) {
      issues.push('Search should use CIM data model fields where possible');
    }
  }

  return issues;
}

const QA_REVIEWER_PROMPT = `You are a detection quality assurance specialist. Review each detection YAML for quality and completeness.

Check for:
- MITRE ATT&CK techniques valid and relevant
- Description explains WHAT the detection finds and WHY it matters (not generic)
- Known false positives documented
- Implementation requirements clear (how_to_implement)
- Test data or validation evidence present
- Filter macro follows detection_name_filter pattern
- Search uses correct data model fields

Return pass/fail/needs_improvement with specific issues. Be concise.

Detections to review (YAML content):
`;

export async function qaReviewerNode(state: PipelineState): Promise<Partial<PipelineState>> {
  console.log('[QA Reviewer] Reviewing detection quality...');

  const cfg = getConfig();

  if (state.detections.length === 0) {
    console.log('[QA Reviewer] No detections to review');
    return { current_step: 'qa_review_complete' };
  }

  if (cfg.dryRun || !cfg.anthropicApiKey) {
    console.log('[QA Reviewer] Dry-run mode - returning mock pass results');
    const mockDetections: Detection[] = state.detections.map(d => ({
      ...d,
      qa_status: 'pass' as const,
      qa_issues: [],
    }));
    mockDetections.forEach(d => console.log(`  - ${d.name}: pass`));
    return {
      detections: mockDetections,
      current_step: 'qa_review_complete',
      warnings: ['Dry-run mode: mock QA results, no LLM call made'],
    };
  }

  const model = new ChatAnthropic({
    modelName: cfg.llmModel,
    temperature: 0,
  });
  const structuredModel = model.withStructuredOutput(QAReviewResponseSchema);

  const updatedDetections: Detection[] = [];
  const needsLLM: Detection[] = [];
  const yamlContents: string[] = [];

  for (const detection of state.detections) {
    const doc = loadDetectionYaml(detection.file_path);
    const progIssues = doc ? programmaticChecks(doc, detection.name) : ['Could not load detection file'];

    if (progIssues.length > 0) {
      updatedDetections.push({
        ...detection,
        qa_status: 'fail' as const,
        qa_issues: progIssues,
      });
      console.log(`[QA Reviewer] ${detection.name}: fail (programmatic) - ${progIssues.join('; ')}`);
    } else {
      updatedDetections.push({ ...detection });
      needsLLM.push(detection);
      const yamlContent = doc ? `\n---\nDetection: ${detection.name}\n${JSON.stringify(doc, null, 2)}\n` : '';
      yamlContents.push(yamlContent);
    }
  }
  if (needsLLM.length === 0) {
    return {
      detections: updatedDetections,
      current_step: 'qa_review_complete',
    };
  }

  try {
    const prompt = QA_REVIEWER_PROMPT + yamlContents.join('\n');
    const response = await structuredModel.invoke(prompt);
    const reviews = response.reviews || [];

    for (let i = 0; i < needsLLM.length && i < reviews.length; i++) {
      const det = needsLLM[i];
      const rev = reviews[i];
      const idx = updatedDetections.findIndex(d => d.id === det.id);
      if (idx >= 0) {
        updatedDetections[idx] = {
          ...updatedDetections[idx],
          qa_status: rev.overall_status,
          qa_issues: rev.issues && rev.issues.length > 0 ? rev.issues : undefined,
        };
        console.log(`[QA Reviewer] ${det.name}: ${rev.overall_status} - ${rev.summary}`);
      }
    }
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    console.error('[QA Reviewer] LLM error:', errorMsg);
    return {
      errors: [errorMsg],
      current_step: 'qa_review_failed',
    };
  }

  return {
    detections: updatedDetections,
    current_step: 'qa_review_complete',
  };
}
