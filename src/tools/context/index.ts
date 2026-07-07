// Context tools - detection-as-prompt compiler
//
// compile_detection_context turns a corpus detection (rule logic) into the typed
// investigative-context object that an agentic SOC's intake/context-assembly
// stage ingests at alert time.
//
// The REUSABLE half (threat model, FP shape, investigation goals) is derived from
// the corpus + ATT&CK siblings. The ENVIRONMENT half (behavioral baselines, prior
// investigation outcomes, asset criticality, tenant scope) is typed-but-empty by
// construction: the compiler creates the slot, it never fabricates the content.
// completeness + warnings make the missing half visible to the consumer.

import { defineTool, type ToolDefinition } from '../registry.js';
import { getDetectionById, listByMitre } from '../../db/index.js';
import { requestSampling } from '../../handlers/sampling.js';

// ---------------------------------------------------------------------------
// Output contract consumed by the downstream SOC. Versioned - bump on change.
// ---------------------------------------------------------------------------
export interface DetectionContext {
  schema_version: '1.0';
  detection_id: string;
  source_type: string;
  name: string;

  // Investigative-prompt half (the point of the compiler)
  threat_model_statement: string;      // what adversary behavior, why it matters
  what_legitimate_looks_like: string;  // benign shape - kills false positives
  risk_criteria: string[];             // conditions that raise/lower severity
  investigation_goals: string[];       // what must be established
  escalation_criteria: string[];       // when this becomes an incident
  hunt_pivots: string[];               // next queries/entities to pivot on
  data_requirements: string[];         // telemetry the investigation needs

  // ATT&CK grounding + provenance join keys
  mitre_techniques: string[];
  mitre_tactics: string[];
  sibling_detection_ids: string[];     // other corpus rules for same technique(s)

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
  };
  completeness: number;                // 0..1 - < 1 signals unfilled env slots
  warnings: string[];
}

const CORPUS_FIELDS = ['description', 'falsepositives', 'data_sources', 'mitre_ids', 'mitre_tactics', 'tags', 'references'];

function buildInvestigativePrompt(det: Record<string, unknown>, siblings: Array<Record<string, unknown>>): string {
  const fp = (det.falsepositives as string[] | undefined) ?? [];
  const siblingBlock = siblings
    .slice(0, 15)
    .map((s) => `- ${String(s.name ?? '')}: ${String(s.description ?? '').slice(0, 240)}${(s.falsepositives as string[] | undefined)?.length ? ` [FP: ${(s.falsepositives as string[]).join('; ')}]` : ''}`)
    .join('\n');

  return [
    'Produce a machine-ingestable investigative-context object for the detection below.',
    'Output STRICT JSON ONLY with exactly these keys: threat_model_statement (string), what_legitimate_looks_like (string), risk_criteria (string[]), investigation_goals (string[]), escalation_criteria (string[]), hunt_pivots (string[]).',
    'Do NOT invent environment-specific facts (behavioral baselines, asset criticality, tenant scope) - those are supplied by the caller, not you.',
    '',
    `DETECTION: ${String(det.name ?? '')}`,
    `SOURCE: ${String(det.source_type ?? '')}`,
    `TECHNIQUES: ${((det.mitre_ids as string[] | undefined) ?? []).join(', ')}`,
    `DESCRIPTION: ${String(det.description ?? '')}`,
    fp.length ? `KNOWN FALSE POSITIVES: ${fp.join('; ')}` : '',
    `QUERY: ${String(det.query ?? '').slice(0, 1200)}`,
    '',
    'SIBLING DETECTIONS FOR THE SAME TECHNIQUE(S) (collective investigation logic to distill):',
    siblingBlock || '(none)',
  ].filter(Boolean).join('\n');
}

function tryParseJson(text: string): Record<string, unknown> | null {
  // Tolerate models that wrap JSON in prose or fenced code blocks.
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

  const det = getDetectionById(detectionId) as Record<string, unknown> | null;
  if (!det) {
    return { error: true, code: 'NOT_FOUND', message: `Detection not found: ${detectionId}` };
  }

  const useSampling = args.use_sampling !== false;
  const techniques = ((det.mitre_ids as string[] | undefined) ?? []).slice();

  // Gather ATT&CK siblings - the accumulated investigation/FP wisdom for the
  // same technique(s). Cap breadth so a broad technique (e.g. T1078.004 ~ 153
  // rules) doesn't blow up the prompt.
  const seen = new Set<string>([detectionId]);
  const siblingDetections: Array<Record<string, unknown>> = [];
  for (const t of techniques.slice(0, 3)) {
    const rules = (listByMitre(t, 25, 0) as Array<Record<string, unknown>>) ?? [];
    for (const r of rules) {
      const id = String(r.id ?? '');
      if (!id || seen.has(id)) continue;
      seen.add(id);
      siblingDetections.push(r);
      if (siblingDetections.length >= 40) break;
    }
    if (siblingDetections.length >= 40) break;
  }

  const warnings: string[] = [];

  const ctx: DetectionContext = {
    schema_version: '1.0',
    detection_id: detectionId,
    source_type: String(det.source_type ?? ''),
    name: String(det.name ?? ''),
    // Deterministic floor - always populated from corpus fields.
    threat_model_statement: String(det.description ?? ''),
    what_legitimate_looks_like: ((det.falsepositives as string[] | undefined) ?? []).join('; '),
    risk_criteria: [],
    investigation_goals: [],
    escalation_criteria: [],
    hunt_pivots: [],
    data_requirements: ((det.data_sources as string[] | undefined) ?? []).slice(),
    mitre_techniques: techniques,
    mitre_tactics: ((det.mitre_tactics as string[] | undefined) ?? []).slice(),
    sibling_detection_ids: siblingDetections.map((s) => String(s.id ?? '')),
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
    },
    completeness: 0.5,
    warnings,
  };

  // Optional LLM synthesis of the prose slots via MCP sampling (uses the
  // client's model - no server-side API key). Nulls out gracefully.
  if (useSampling) {
    const sampled = await requestSampling({
      messages: [{ role: 'user', content: { type: 'text', text: buildInvestigativePrompt(det, siblingDetections) } }],
      systemPrompt:
        'You are a senior detection engineer producing a machine-ingestable investigative-context object for an autonomous SOC. Output STRICT JSON only. Be specific and technical. Never fabricate environment-specific facts (baselines, asset criticality, tenant scope).',
      maxTokens: 1500,
      temperature: 0.2,
    });

    if (sampled && sampled.content && typeof sampled.content.text === 'string') {
      const parsed = tryParseJson(sampled.content.text);
      if (parsed) {
        if (typeof parsed.threat_model_statement === 'string') ctx.threat_model_statement = parsed.threat_model_statement;
        if (typeof parsed.what_legitimate_looks_like === 'string') ctx.what_legitimate_looks_like = parsed.what_legitimate_looks_like;
        if (Array.isArray(parsed.risk_criteria)) ctx.risk_criteria = parsed.risk_criteria as string[];
        if (Array.isArray(parsed.investigation_goals)) ctx.investigation_goals = parsed.investigation_goals as string[];
        if (Array.isArray(parsed.escalation_criteria)) ctx.escalation_criteria = parsed.escalation_criteria as string[];
        if (Array.isArray(parsed.hunt_pivots)) ctx.hunt_pivots = parsed.hunt_pivots as string[];
        ctx.provenance.compiled_from = 'corpus+sampling';
        ctx.provenance.model = sampled.model ?? null;
      } else {
        warnings.push('sampling returned non-JSON; kept deterministic (description + false-positive) fields only');
      }
    } else {
      warnings.push('client does not support MCP sampling; investigative slots are deterministic-only (description + false positives)');
    }
  }

  // Environment half is empty by construction - say so, loudly. This is the
  // signal that the consuming SOC must supply org context before verdicts rely
  // on this object.
  warnings.push('environment_context is empty: behavioral baselines, prior investigation outcomes, asset criticality, and tenant scope must be supplied by the consuming SOC before verdicts depend on this context');

  // completeness reflects both halves: env slots are always empty here, so it is
  // capped well below 1.0 even with sampling.
  ctx.completeness = ctx.provenance.compiled_from === 'corpus+sampling' ? 0.7 : 0.5;

  return ctx;
}

export const detectionContextTools: ToolDefinition[] = [
  defineTool({
    name: 'compile_detection_context',
    description:
      'Compile a detection into a typed "detection-as-prompt" investigative-context object (threat-model statement, what-legitimate-looks-like, risk criteria, investigation goals, escalation criteria, hunt pivots) for downstream agentic-SOC context assembly. Draws the reusable half from the corpus + ATT&CK siblings; optionally synthesizes prose slots via MCP sampling with a deterministic fallback. Environment-specific slots (baselines, prior outcomes, asset criticality, tenant scope) are left typed-but-empty and surfaced via warnings + a completeness score.',
    inputSchema: {
      type: 'object',
      properties: {
        detection_id: {
          type: 'string',
          description: 'Corpus detection id (from get_by_id / list_by_mitre / search)',
        },
        use_sampling: {
          type: 'boolean',
          description: 'Synthesize prose slots via MCP sampling when the client supports it (default true). Falls back to deterministic fields otherwise.',
        },
      },
      required: ['detection_id'],
    },
    handler: compileHandler,
    icon: '\u{1F9E9}',
  }),
];

export const detectionContextToolCount = detectionContextTools.length;
