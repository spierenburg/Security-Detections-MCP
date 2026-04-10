import { readFileSync } from 'fs';
import { parse as parseYaml } from 'yaml';
import { createHash } from 'crypto';
import type { Detection, SublimeRule } from '../types.js';

// Best-effort mapping from Sublime tactics_and_techniques to MITRE ATT&CK tactics
const TACTICS_MAP: Record<string, string> = {
  'evasion': 'defense-evasion',
  'exploit': 'execution',
  'social engineering': 'initial-access',
  'impersonation: brand': 'initial-access',
  'impersonation: employee': 'initial-access',
  'impersonation: vip': 'initial-access',
  'lookalike domain': 'initial-access',
  'spoofing': 'initial-access',
  'scripting': 'execution',
  'macros': 'execution',
  'encryption': 'defense-evasion',
};

// Map Sublime attack_types and tactics_and_techniques to MITRE technique IDs
const ATTACK_TYPE_TO_MITRE: Record<string, string[]> = {
  'credential phishing': ['T1566', 'T1566.001', 'T1566.002', 'T1598'],
  'bec/fraud': ['T1566.002', 'T1534', 'T1656'],
  'malware/ransomware': ['T1566.001', 'T1204.002', 'T1486'],
  'spam': ['T1566'],
  'callback phishing': ['T1566.003', 'T1598'],
  'extortion': ['T1486', 'T1657'],
};

const TACTIC_TO_MITRE: Record<string, string[]> = {
  'social engineering': ['T1566', 'T1598'],
  'impersonation: brand': ['T1566.002', 'T1598.003'],
  'impersonation: employee': ['T1566.002', 'T1534'],
  'impersonation: vip': ['T1566.002', 'T1534'],
  'spoofing': ['T1566', 'T1598'],
  'lookalike domain': ['T1583.001', 'T1566.002'],
  'exploit': ['T1190', 'T1203'],
  'macros': ['T1204.002', 'T1059.005'],
  'scripting': ['T1059'],
  'evasion': ['T1036', 'T1027'],
  'encryption': ['T1027', 'T1573'],
};

function extractMitreIds(attackTypes: string[] | undefined, tactics: string[] | undefined): string[] {
  const ids = new Set<string>();
  if (attackTypes) {
    for (const at of attackTypes) {
      const mapped = ATTACK_TYPE_TO_MITRE[at.toLowerCase()];
      if (mapped) mapped.forEach(id => ids.add(id));
    }
  }
  if (tactics) {
    for (const t of tactics) {
      const mapped = TACTIC_TO_MITRE[t.toLowerCase()];
      if (mapped) mapped.forEach(id => ids.add(id));
    }
  }
  return [...ids];
}

// Generate a stable ID from file path and rule name
function generateId(filePath: string, name: string): string {
  const hash = createHash('sha256')
    .update(`${filePath}:${name}`)
    .digest('hex')
    .substring(0, 32);
  return `sublime-${hash}`;
}

// Extract author names from the authors array
function extractAuthorNames(authors: SublimeRule['authors']): string | null {
  if (!authors || authors.length === 0) return null;
  const names = authors
    .map(a => a.name || a.twitter || a.github || 'Unknown')
    .filter(Boolean);
  return names.length > 0 ? names.join(', ') : null;
}

// Map Sublime tactics to MITRE ATT&CK tactics (best-effort)
function mapToMitreTactics(tactics: string[] | undefined): string[] {
  if (!tactics) return [];
  const mitreTactics = new Set<string>();
  for (const tactic of tactics) {
    const mapped = TACTICS_MAP[tactic.toLowerCase()];
    if (mapped) {
      mitreTactics.add(mapped);
    }
  }
  return [...mitreTactics];
}

export function parseSublimeFile(filePath: string): Detection | null {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const rule = parseYaml(content) as SublimeRule;

    // name and source are required
    if (!rule.name || !rule.source) {
      return null;
    }

    // type must be 'rule' or 'exclusion'
    if (rule.type !== 'rule' && rule.type !== 'exclusion') {
      return null;
    }

    const id = rule.id || generateId(filePath, rule.name);

    const detection: Detection = {
      id,
      name: rule.name,
      description: rule.description || '',
      query: rule.source,
      source_type: 'sublime',
      mitre_ids: extractMitreIds(rule.attack_types, rule.tactics_and_techniques),
      logsource_category: 'email',
      logsource_product: 'email',
      logsource_service: null,
      severity: rule.severity || null,
      status: null,
      author: extractAuthorNames(rule.authors),
      date_created: null,
      date_modified: null,
      references: rule.references || [],
      falsepositives: rule.false_positives || [],
      tags: rule.tags || [],
      file_path: filePath,
      raw_yaml: content,

      cves: [],
      analytic_stories: [],
      data_sources: ['Email Messages', 'Email Headers', 'Email Attachments'],
      detection_type: rule.type === 'exclusion' ? 'Exclusion' : 'Rule',
      asset_type: 'Email',
      security_domain: 'access',
      process_names: [],
      file_paths: [],
      registry_paths: [],
      mitre_tactics: mapToMitreTactics(rule.tactics_and_techniques),
      platforms: ['email'],
      kql_category: null,
      kql_tags: [],
      kql_keywords: [],

      // Sublime-specific fields
      sublime_attack_types: rule.attack_types || [],
      sublime_detection_methods: rule.detection_methods || [],
      sublime_tactics: rule.tactics_and_techniques || [],
    };

    return detection;
  } catch {
    // Skip files that can't be parsed
    return null;
  }
}
