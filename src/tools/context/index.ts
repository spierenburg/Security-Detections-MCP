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

// Only fields the handler actually reads from each detection record. Kept honest
// so provenance.corpus_fields_used is a truthful audit trail.
const CORPUS_FIELDS = ['description', 'falsepositives', 'data_sources', 'mitre_ids', 'mitre_tactics'];

// Light projection of a sibling detection - just what the prompt/ids need, so we
// don't retain full records (raw_yaml, query) across the sampling await.
interface SiblingLite {
  id: string;
  name: string;
  description: string;
  falsepositives: string[];
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
    'Output STRICT JSON ONLY with exactly these keys: threat_model_statement (string), what_legitimate_looks_like (string), risk_criteria (string[]), investigation_goals (string[]), escalation_criteria (string[]), hunt_pivots (string[]).',
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

  const det = getDetectionById(detectionId) as unknown as Record<string, unknown> | null;
  if (!det) {
    return { error: true, code: 'NOT_FOUND', message: `Detection not found: ${detectionId}` };
  }

  const useSampling = args.use_sampling !== false;
  const techniques = toStringArray(det.mitre_ids);

  // Gather ATT&CK siblings - the accumulated investigation/FP wisdom for the
  // same technique(s). Project to a light shape immediately so full records
  // (raw_yaml, query) don't linger across the sampling await. Cap breadth so a
  // broad technique (e.g. T1078.004 ~ 153 rules) doesn't blow up the prompt.
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
    schema_version: '1.0',
    detection_id: detectionId,
    source_type: String(det.source_type ?? ''),
    name: String(det.name ?? ''),
    // Deterministic floor - always populated from corpus fields.
    threat_model_statement: String(det.description ?? ''),
    what_legitimate_looks_like: toStringArray(det.falsepositives).join('; '),
    risk_criteria: [],
    investigation_goals: [],
    escalation_criteria: [],
    hunt_pivots: [],
    data_requirements: toStringArray(det.data_sources),
    mitre_techniques: techniques,
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
    },
    // Deterministic default; only advances when sampling actually contributes.
    completeness: 0.5,
    warnings,
  };

  // Optional LLM synthesis of the prose slots via MCP sampling (uses the
  // client's model - no server-side API key). Nulls out gracefully, and a
  // sampled value only REPLACES a deterministic one when it is non-empty, so a
  // blank completion can never degrade the object below the deterministic floor.
  if (useSampling) {
    const sampled = await requestSampling({
      messages: [{ role: 'user', content: { type: 'text', text: buildInvestigativePrompt(det, siblings) } }],
      systemPrompt:
        'You are a senior detection engineer producing a machine-ingestable investigative-context object for an autonomous SOC. Output STRICT JSON only. Be specific and technical. Never fabricate environment-specific facts (baselines, asset criticality, tenant scope).',
      maxTokens: 1500,
      temperature: 0.2,
    });

    if (sampled && sampled.content && typeof sampled.content.text === 'string') {
      const parsed = tryParseJson(sampled.content.text);
      if (parsed) {
        let appliedAny = false;
        const tms = nonEmptyString(parsed.threat_model_statement);
        if (tms) { ctx.threat_model_statement = tms; appliedAny = true; }
        const wl = nonEmptyString(parsed.what_legitimate_looks_like);
        if (wl) { ctx.what_legitimate_looks_like = wl; appliedAny = true; }
        const rc = toStringArray(parsed.risk_criteria);
        if (rc.length) { ctx.risk_criteria = rc; appliedAny = true; }
        const ig = toStringArray(parsed.investigation_goals);
        if (ig.length) { ctx.investigation_goals = ig; appliedAny = true; }
        const ec = toStringArray(parsed.escalation_criteria);
        if (ec.length) { ctx.escalation_criteria = ec; appliedAny = true; }
        const hp = toStringArray(parsed.hunt_pivots);
        if (hp.length) { ctx.hunt_pivots = hp; appliedAny = true; }

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

  // Environment half is empty by construction - say so, loudly. This is the
  // signal that the consuming SOC must supply org context before verdicts rely
  // on this object. (completeness stays <= 0.7 because these slots are unfilled.)
  warnings.push('environment_context is empty: behavioral baselines, prior investigation outcomes, asset criticality, and tenant scope must be supplied by the consuming SOC before verdicts depend on this context');

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
