// Context tools - detection-as-prompt compiler (v1.1)
//
// compile_detection_context turns a corpus detection (rule logic) into the typed
// investigative-context object that an agentic SOC's intake/context-assembly
// stage ingests. v1.1 aligns the output to cognitive-soc's detection-judgment
// corpus (JudgmentDoc): see cognitive-soc/docs/contracts/detection-as-prompt.md.
//
// The REUSABLE half (threat model, risk criteria, investigation goals) is derived
// from the corpus + ATT&CK siblings. The ENVIRONMENT half (baselines, prior
// outcomes, asset criticality, tenant scope) is typed-but-empty by construction:
// the compiler creates the slot, never fabricates the content. completeness +
// warnings make the missing half visible.

import { defineTool, type ToolDefinition } from '../registry.js';
import { getDetectionById, listByMitre } from '../../db/index.js';
import { requestSampling } from '../../handlers/sampling.js';

// ---------------------------------------------------------------------------
// Output contract. Mirrors cognitive-soc JudgmentDoc field shapes so a thin
// consumer-side adapter maps it 1:1. Versioned - bump on change.
// ---------------------------------------------------------------------------
export interface ThreatModel {
  adversary_behavior: string;   // what the detection looks for, in adversary terms
  why_it_matters: string;       // impact when the behavior is real
  legitimate_pattern: string;   // the same observable when benign (FP surface)
  mitre_techniques: string[];
}

export interface RiskCriteria {
  malicious_indicators: string[];
  benign_indicators: string[];
  required_corroboration: string[];
  false_positive_callouts: string[];
}

export interface DetectionContext {
  schema_version: '1.1';
  detection_id: string;
  source_type: string;
  name: string;

  // Investigative-prompt half (the point of the compiler)
  threat_model: ThreatModel;
  risk_criteria: RiskCriteria;
  investigation_goals: string[];
  enrichment_sources: string[];

  // ATT&CK grounding + provenance join keys
  mitre_tactics: string[];
  sibling_detection_ids: string[];

  // Environment half - TYPED BUT EMPTY until the consuming SOC fills it.
  environment_context: {
    behavioral_baselines: string[];
    prior_investigation_outcomes: string[];
    asset_criticality: string | null;
    tenant_scope: string | null;
  };

  provenance: {
    compiled_from: 'corpus' | 'corpus+sampling';
    corpus_fields_used: string[];
    model: string | null;
    generated_at: string;
    // Suggested cognitive-soc JudgmentDoc content_status for this output.
    // 'reference' only when the full judgment set is present; 'draft' otherwise.
    // Never 'active' - that requires human review (schema.json active gate).
    suggested_content_status: 'reference' | 'draft';
  };
  completeness: number;
  warnings: string[];
}

// Only fields the handler actually reads from each detection record.
const CORPUS_FIELDS = ['description', 'falsepositives', 'data_sources', 'mitre_ids', 'mitre_tactics'];

interface SiblingLite {
  id: string;
  name: string;
  description: string;
  falsepositives: string[];
}

function isRecord(v: unknown): v is Record<string, unknown> {
  return typeof v === 'object' && v !== null && !Array.isArray(v);
}

function toStringArray(v: unknown): string[] {
  return Array.isArray(v) ? (v as unknown[]).filter((x): x is string => typeof x === 'string') : [];
}

function nonEmptyString(v: unknown): string | undefined {
  return typeof v === 'string' && v.trim() ? v : undefined;
}

function buildInvestigativePrompt(det: Record<string, unknown>, siblings: SiblingLite[]): string {
  const fp = toStringArray(det.falsepositives);
  const siblingBlock = siblings
    .slice(0, 15)
    .map((s) => `- ${s.name}: ${s.description.slice(0, 240)}${s.falsepositives.length ? ` [FP: ${s.falsepositives.join('; ')}]` : ''}`)
    .join('\n');

  return [
    'Produce a machine-ingestable investigative-context object for the detection below.',
    'Output STRICT JSON ONLY with exactly these keys:',
    '  threat_model: { adversary_behavior: string, why_it_matters: string, legitimate_pattern: string },',
    '  risk_criteria: { malicious_indicators: string[], benign_indicators: string[], required_corroboration: string[], false_positive_callouts: string[] },',
    '  investigation_goals: string[]',
    'adversary_behavior = what the detection looks for in adversary-action terms; why_it_matters = impact when real; legitimate_pattern = the same observable when benign.',
    'risk_criteria lists are instance-level rubrics: malicious_indicators raise risk, benign_indicators lower it, required_corroboration is what must be checked, false_positive_callouts are known benign causes.',
    'Do NOT invent environment-specific facts (behavioral baselines, asset criticality, tenant scope) - those are supplied by the caller, not you.',
    '',
    `DETECTION: ${String(det.name ?? '')}`,
    `SOURCE: ${String(det.source_type ?? '')}`,
    `TECHNIQUES: ${toStringArray(det.mitre_ids).join(', ')}`,
    `DESCRIPTION: ${String(det.description ?? '')}`,
    fp.length ? `KNOWN FALSE POSITIVES: ${fp.join('; ')}` : '',
    `QUERY: ${String(det.query ?? '').slice(0, 1200)}`,
    '',
    'SIBLING DETECTIONS FOR THE SAME TECHNIQUE(S) (collective investigation logic to distill):',
    siblingBlock || '(none)',
  ].filter(Boolean).join('\n');
}

function tryParseJson(text: string): Record<string, unknown> | null {
  const fenced = text.match(/```(?:json)?\s*([\s\S]*?)```/i);
  const candidate = fenced ? fenced[1] : text;
  const start = candidate.indexOf('{');
  const end = candidate.lastIndexOf('}');
  if (start === -1 || end === -1 || end <= start) return null;
  try {
    return JSON.parse(candidate.slice(start, end + 1)) as Record<string, unknown>;
  } catch {
    return null;
  }
}

async function compileHandler(args: Record<string, unknown>): Promise<DetectionContext | { error: true; code?: string; message: string }> {
  const detectionId = String(args.detection_id ?? '');
  if (!detectionId) {
    return { error: true, code: 'MISSING_REQUIRED_ARG', message: 'detection_id is required' };
  }

  const det = getDetectionById(detectionId) as unknown as Record<string, unknown> | null;
  if (!det) {
    return { error: true, code: 'NOT_FOUND', message: `Detection not found: ${detectionId}` };
  }

  const useSampling = args.use_sampling !== false;
  const techniques = toStringArray(det.mitre_ids);

  // Gather ATT&CK siblings, projected to a light shape so full records
  // (raw_yaml, query) don't linger across the sampling await. Cap breadth.
  const seen = new Set<string>([detectionId]);
  const siblings: SiblingLite[] = [];
  for (const t of techniques.slice(0, 3)) {
    const rules = (listByMitre(t, 25, 0) as unknown as Array<Record<string, unknown>>) ?? [];
    for (const r of rules) {
      const id = String(r.id ?? '');
      if (!id || seen.has(id)) continue;
      seen.add(id);
      siblings.push({
        id,
        name: String(r.name ?? ''),
        description: String(r.description ?? ''),
        falsepositives: toStringArray(r.falsepositives),
      });
      if (siblings.length >= 40) break;
    }
    if (siblings.length >= 40) break;
  }

  const warnings: string[] = [];

  const ctx: DetectionContext = {
    schema_version: '1.1',
    detection_id: detectionId,
    source_type: String(det.source_type ?? ''),
    name: String(det.name ?? ''),
    // Deterministic floor from corpus fields. why_it_matters + the four-list
    // risk criteria + investigation_goals are sampling-only (never invented).
    threat_model: {
      adversary_behavior: String(det.description ?? ''),
      why_it_matters: '',
      legitimate_pattern: toStringArray(det.falsepositives).join('; '),
      mitre_techniques: techniques,
    },
    risk_criteria: {
      malicious_indicators: [],
      benign_indicators: [],
      required_corroboration: [],
      false_positive_callouts: [],
    },
    investigation_goals: [],
    enrichment_sources: toStringArray(det.data_sources),
    mitre_tactics: toStringArray(det.mitre_tactics),
    sibling_detection_ids: siblings.map((s) => s.id),
    environment_context: {
      behavioral_baselines: [],
      prior_investigation_outcomes: [],
      asset_criticality: null,
      tenant_scope: null,
    },
    provenance: {
      compiled_from: 'corpus',
      corpus_fields_used: CORPUS_FIELDS,
      model: null,
      generated_at: new Date().toISOString(),
      suggested_content_status: 'draft',
    },
    completeness: 0.5,
    warnings,
  };

  // Optional LLM synthesis via MCP sampling (client's model - no server key).
  // A sampled value only REPLACES a deterministic one when non-empty, so a blank
  // completion can never degrade the object below the deterministic floor.
  if (useSampling) {
    const sampled = await requestSampling({
      messages: [{ role: 'user', content: { type: 'text', text: buildInvestigativePrompt(det, siblings) } }],
      systemPrompt:
        'You are a senior detection engineer producing a machine-ingestable investigative-context object for an autonomous SOC. Output STRICT JSON only, matching the requested nested shape. Be specific and technical. Never fabricate environment-specific facts (baselines, asset criticality, tenant scope).',
      maxTokens: 1500,
      temperature: 0.2,
    });

    if (sampled && sampled.content && typeof sampled.content.text === 'string') {
      const parsed = tryParseJson(sampled.content.text);
      if (parsed) {
        let appliedAny = false;
        const tm = isRecord(parsed.threat_model) ? parsed.threat_model : {};
        const ab = nonEmptyString(tm.adversary_behavior);
        if (ab) { ctx.threat_model.adversary_behavior = ab; appliedAny = true; }
        const wm = nonEmptyString(tm.why_it_matters);
        if (wm) { ctx.threat_model.why_it_matters = wm; appliedAny = true; }
        const lp = nonEmptyString(tm.legitimate_pattern);
        if (lp) { ctx.threat_model.legitimate_pattern = lp; appliedAny = true; }

        const rc = isRecord(parsed.risk_criteria) ? parsed.risk_criteria : {};
        const mal = toStringArray(rc.malicious_indicators);
        if (mal.length) { ctx.risk_criteria.malicious_indicators = mal; appliedAny = true; }
        const ben = toStringArray(rc.benign_indicators);
        if (ben.length) { ctx.risk_criteria.benign_indicators = ben; appliedAny = true; }
        const req = toStringArray(rc.required_corroboration);
        if (req.length) { ctx.risk_criteria.required_corroboration = req; appliedAny = true; }
        const fpc = toStringArray(rc.false_positive_callouts);
        if (fpc.length) { ctx.risk_criteria.false_positive_callouts = fpc; appliedAny = true; }

        const ig = toStringArray(parsed.investigation_goals);
        if (ig.length) { ctx.investigation_goals = ig; appliedAny = true; }

        if (appliedAny) {
          ctx.provenance.compiled_from = 'corpus+sampling';
          ctx.provenance.model = sampled.model ?? null;
          ctx.completeness = 0.7;
        } else {
          warnings.push('sampling returned JSON but no usable fields; kept deterministic values');
        }
      } else {
        warnings.push('sampling returned non-JSON; kept deterministic (description + false-positive) fields only');
      }
    } else {
      warnings.push('client does not support MCP sampling; investigative slots are deterministic-only (description + false positives)');
    }
  }

  // Environment half is empty by construction - say so, loudly.
  warnings.push('environment_context is empty: behavioral baselines, prior investigation outcomes, asset criticality, and tenant scope must be supplied by the consuming SOC before verdicts depend on this context');

  // Suggested JudgmentDoc content_status (contract §5): 'reference' requires the
  // full active/reference content set; otherwise 'draft'. Never 'active'.
  const tmComplete =
    !!ctx.threat_model.adversary_behavior.trim() &&
    !!ctx.threat_model.why_it_matters.trim() &&
    !!ctx.threat_model.legitimate_pattern.trim();
  const rcComplete =
    ctx.risk_criteria.malicious_indicators.length > 0 &&
    ctx.risk_criteria.benign_indicators.length > 0 &&
    ctx.risk_criteria.required_corroboration.length > 0;
  const goalsComplete = ctx.investigation_goals.length > 0;
  ctx.provenance.suggested_content_status = tmComplete && rcComplete && goalsComplete ? 'reference' : 'draft';

  return ctx;
}

export const detectionContextTools: ToolDefinition[] = [
  defineTool({
    name: 'compile_detection_context',
    description:
      'Compile a detection into a typed "detection-as-prompt" investigative-context object for downstream agentic-SOC context assembly. Output is aligned to the cognitive-soc JudgmentDoc shape: threat_model{adversary_behavior, why_it_matters, legitimate_pattern, mitre_techniques}, risk_criteria{malicious_indicators, benign_indicators, required_corroboration, false_positive_callouts}, investigation_goals, enrichment_sources. Draws the reusable half from the corpus + ATT&CK siblings; optionally synthesizes the prose/rubric slots via MCP sampling with a deterministic fallback. Environment-specific slots are left typed-but-empty and surfaced via warnings + a completeness score. provenance.suggested_content_status indicates whether the output is corpus-complete (reference) or floor-only (draft).',
    inputSchema: {
      type: 'object',
      properties: {
        detection_id: {
          type: 'string',
          description: 'Corpus detection id (from get_by_id / list_by_mitre / search)',
        },
        use_sampling: {
          type: 'boolean',
          description: 'Synthesize the rubric/prose slots via MCP sampling when the client supports it (default true). Falls back to deterministic fields otherwise.',
        },
      },
      required: ['detection_id'],
    },
    handler: compileHandler,
    icon: '\u{1F9E9}',
  }),
];

export const detectionContextToolCount = detectionContextTools.length;
