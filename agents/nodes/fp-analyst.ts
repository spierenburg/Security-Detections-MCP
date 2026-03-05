import { ChatAnthropic } from '@langchain/anthropic';
import { readFileSync, existsSync } from 'fs';
import { resolve } from 'path';
import yaml from 'js-yaml';
import { getConfig } from '../config.js';
import type { PipelineState, Detection } from '../state/types.js';
import { z } from 'zod';

const FPAssessmentSchema = z.object({
  risk: z.enum(['low', 'medium', 'high', 'critical']).describe('FP risk level'),
  recommendations: z.array(z.string()).describe('Tuning recommendations'),
  reasoning: z.string().describe('Brief explanation of risk assessment'),
});

const FPAssessmentResponseSchema = z.object({
  assessments: z.array(FPAssessmentSchema).describe('One assessment per detection'),
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

const FP_ANALYST_PROMPT = `You are a false positive risk analyst for detection rules. Assess each detection's search logic for FP-prone patterns.

Analyze:
1. Detection logic - overly broad conditions, generic process names (svchost.exe, rundll32.exe without context)
2. Common administrative tools - PowerShell, WMI, Task Scheduler used without sufficient context
3. Missing exclusions for known legitimate software
4. Overly broad network/file patterns (wildcards, loose matching)
5. Absence of baseline or statistical thresholds

Risk scoring:
- Low: Specific IOCs, unlikely legitimate use
- Medium: Administrative tools with some context
- High: Generic patterns, common tools
- Critical: Will fire constantly in most environments

Provide specific tuning recommendations (exclusions, thresholds, contextual enrichment).

Detections to assess (YAML content):
`;

export async function fpAnalystNode(state: PipelineState): Promise<Partial<PipelineState>> {
  console.log('[FP Analyst] Assessing false positive risk...');

  const cfg = getConfig();

  if (state.detections.length === 0) {
    console.log('[FP Analyst] No detections to assess');
    return { current_step: 'fp_assessment_complete' };
  }

  if (cfg.dryRun || !cfg.anthropicApiKey) {
    console.log('[FP Analyst] Dry-run mode - returning mock low-risk assessments');
    const mockDetections: Detection[] = state.detections.map(d => ({
      ...d,
      fp_risk: 'low' as const,
      fp_recommendations: [],
    }));
    mockDetections.forEach(d => console.log(`  - ${d.name}: low`));
    return {
      detections: mockDetections,
      current_step: 'fp_assessment_complete',
      warnings: ['Dry-run mode: mock FP assessments, no LLM call made'],
    };
  }

  const model = new ChatAnthropic({
    modelName: cfg.llmModel,
    temperature: 0,
  });
  const structuredModel = model.withStructuredOutput(FPAssessmentResponseSchema);

  const docsAndDetections: { doc: Record<string, unknown>; detection: Detection }[] = [];
  for (const detection of state.detections) {
    const doc = loadDetectionYaml(detection.file_path);
    if (doc) {
      docsAndDetections.push({ doc, detection });
    }
  }

  if (docsAndDetections.length === 0) {
    console.log('[FP Analyst] No detection files could be loaded');
    return {
      current_step: 'fp_assessment_complete',
      warnings: ['FP Analyst: could not load any detection YAML files'],
    };
  }

  const yamlPayload = docsAndDetections
    .map(({ doc, detection }) => `\n---\nDetection: ${detection.name}\n${JSON.stringify(doc, null, 2)}\n`)
    .join('\n');

  try {
    const prompt = FP_ANALYST_PROMPT + yamlPayload;
    const response = await structuredModel.invoke(prompt);
    const assessments = response.assessments || [];

    const updatedDetections = state.detections.map(d => {
      const idx = docsAndDetections.findIndex(p => p.detection.id === d.id);
      if (idx < 0 || idx >= assessments.length) {
        return d;
      }
      const a = assessments[idx];
      console.log(`[FP Analyst] ${d.name}: ${a.risk} - ${a.reasoning}`);
      return {
        ...d,
        fp_risk: a.risk,
        fp_recommendations: a.recommendations || [],
      };
    });

    const highRisk = updatedDetections.filter(d => d.fp_risk === 'high' || d.fp_risk === 'critical');
    const fpWarnings = highRisk.map(
      d => `FP risk ${d.fp_risk}: ${d.name} - ${d.fp_recommendations?.slice(0, 2).join('; ') || 'see recommendations'}`
    );

    return {
      detections: updatedDetections,
      current_step: 'fp_assessment_complete',
      warnings: state.warnings.concat(fpWarnings),
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    console.error('[FP Analyst] Error:', errorMsg);
    return {
      errors: [errorMsg],
      current_step: 'fp_assessment_failed',
    };
  }
}
