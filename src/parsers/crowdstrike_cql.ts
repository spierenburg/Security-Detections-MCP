import { readFileSync } from 'fs';
import { parse as parseYaml } from 'yaml';
import { createHash } from 'crypto';
import type { Detection, CqlHubRule } from '../types.js';

// MITRE technique ID to tactic(s) mapping (top-level techniques only)
// Some techniques belong to multiple tactics (e.g., T1078 -> initial-access & persistence)
const TECHNIQUE_TO_TACTICS: Record<string, string[]> = {
  'T1595': ['reconnaissance'], 'T1592': ['reconnaissance'], 'T1589': ['reconnaissance'],
  'T1590': ['reconnaissance'], 'T1591': ['reconnaissance'], 'T1598': ['reconnaissance'],
  'T1597': ['reconnaissance'], 'T1596': ['reconnaissance'], 'T1593': ['reconnaissance'],
  'T1594': ['reconnaissance'],
  'T1583': ['resource-development'], 'T1586': ['resource-development'], 'T1584': ['resource-development'],
  'T1587': ['resource-development'], 'T1585': ['resource-development'], 'T1588': ['resource-development'],
  'T1608': ['resource-development'],
  'T1189': ['initial-access'], 'T1190': ['initial-access'],
  'T1200': ['initial-access'], 'T1566': ['initial-access'],
  'T1195': ['initial-access'], 'T1199': ['initial-access'],
  'T1133': ['initial-access', 'persistence'],
  'T1078': ['initial-access', 'persistence', 'privilege-escalation', 'defense-evasion'],
  'T1091': ['initial-access', 'lateral-movement'],
  'T1059': ['execution'], 'T1203': ['execution'], 'T1559': ['execution'],
  'T1106': ['execution'], 'T1129': ['execution'],
  'T1204': ['execution'], 'T1047': ['execution'], 'T1569': ['execution'],
  'T1053': ['execution', 'persistence', 'privilege-escalation'],
  'T1098': ['persistence'], 'T1197': ['persistence'], 'T1547': ['persistence', 'privilege-escalation'],
  'T1037': ['persistence'], 'T1136': ['persistence'], 'T1543': ['persistence', 'privilege-escalation'],
  'T1546': ['persistence', 'privilege-escalation'], 'T1574': ['persistence', 'privilege-escalation'],
  'T1525': ['persistence'], 'T1556': ['persistence', 'credential-access', 'defense-evasion'],
  'T1137': ['persistence'], 'T1542': ['persistence', 'defense-evasion'],
  'T1505': ['persistence'], 'T1205': ['persistence', 'defense-evasion'],
  'T1548': ['privilege-escalation', 'defense-evasion'], 'T1134': ['privilege-escalation', 'defense-evasion'],
  'T1068': ['privilege-escalation'], 'T1484': ['privilege-escalation', 'defense-evasion'],
  'T1611': ['privilege-escalation'],
  'T1562': ['defense-evasion'], 'T1070': ['defense-evasion'], 'T1202': ['defense-evasion'],
  'T1036': ['defense-evasion'], 'T1055': ['defense-evasion', 'privilege-escalation'],
  'T1027': ['defense-evasion'], 'T1218': ['defense-evasion'], 'T1216': ['defense-evasion'],
  'T1220': ['defense-evasion'], 'T1140': ['defense-evasion'], 'T1112': ['defense-evasion'],
  'T1564': ['defense-evasion'],
  'T1003': ['credential-access'], 'T1110': ['credential-access'], 'T1555': ['credential-access'],
  'T1212': ['credential-access'], 'T1187': ['credential-access'], 'T1606': ['credential-access'],
  'T1056': ['credential-access', 'collection'], 'T1557': ['credential-access', 'collection'],
  'T1111': ['credential-access'], 'T1552': ['credential-access'], 'T1558': ['credential-access'],
  'T1539': ['credential-access'], 'T1528': ['credential-access'], 'T1649': ['credential-access'],
  'T1087': ['discovery'], 'T1010': ['discovery'], 'T1217': ['discovery'],
  'T1580': ['discovery'], 'T1538': ['discovery'], 'T1526': ['discovery'],
  'T1482': ['discovery'], 'T1083': ['discovery'], 'T1046': ['discovery'],
  'T1135': ['discovery'], 'T1040': ['discovery', 'credential-access'],
  'T1201': ['discovery'], 'T1120': ['discovery'], 'T1069': ['discovery'],
  'T1057': ['discovery'], 'T1012': ['discovery'], 'T1018': ['discovery'],
  'T1518': ['discovery'], 'T1082': ['discovery'], 'T1016': ['discovery'],
  'T1049': ['discovery'], 'T1033': ['discovery'], 'T1007': ['discovery'],
  'T1124': ['discovery'],
  'T1021': ['lateral-movement'], 'T1072': ['lateral-movement'],
  'T1080': ['lateral-movement'], 'T1550': ['lateral-movement', 'defense-evasion'],
  'T1563': ['lateral-movement'], 'T1570': ['lateral-movement'],
  'T1560': ['collection'], 'T1123': ['collection'], 'T1119': ['collection'],
  'T1115': ['collection'], 'T1530': ['collection'], 'T1602': ['collection'],
  'T1213': ['collection'], 'T1005': ['collection'], 'T1039': ['collection'],
  'T1025': ['collection'], 'T1074': ['collection'], 'T1114': ['collection'],
  'T1113': ['collection'], 'T1125': ['collection'],
  'T1071': ['command-and-control'], 'T1132': ['command-and-control'],
  'T1001': ['command-and-control'], 'T1568': ['command-and-control'],
  'T1573': ['command-and-control'], 'T1008': ['command-and-control'],
  'T1105': ['command-and-control'], 'T1104': ['command-and-control'],
  'T1095': ['command-and-control'], 'T1571': ['command-and-control'],
  'T1572': ['command-and-control'], 'T1090': ['command-and-control'],
  'T1219': ['command-and-control'], 'T1102': ['command-and-control'],
  'T1048': ['exfiltration'], 'T1041': ['exfiltration'], 'T1011': ['exfiltration'],
  'T1052': ['exfiltration'], 'T1567': ['exfiltration'], 'T1029': ['exfiltration'],
  'T1537': ['exfiltration'],
  'T1531': ['impact'], 'T1485': ['impact'], 'T1486': ['impact'],
  'T1565': ['impact'], 'T1491': ['impact'], 'T1561': ['impact'],
  'T1499': ['impact'], 'T1495': ['impact'], 'T1489': ['impact'],
  'T1490': ['impact'], 'T1498': ['impact'], 'T1496': ['impact'],
};

// Generate a stable ID from file path and rule name
function generateId(filePath: string, name: string): string {
  const hash = createHash('sha256')
    .update(`${filePath}:${name}`)
    .digest('hex')
    .substring(0, 32);
  return `crowdstrike-cql-${hash}`;
}

// Extract MITRE tactics from technique IDs
function extractMitreTactics(mitreIds: string[]): string[] {
  const tactics = new Set<string>();
  for (const id of mitreIds) {
    // Get the parent technique ID (T1003.001 -> T1003)
    const parentId = id.split('.')[0];
    const mapped = TECHNIQUE_TO_TACTICS[parentId];
    if (mapped) {
      for (const tactic of mapped) {
        tactics.add(tactic);
      }
    }
  }
  return [...tactics];
}

// Extract process names from CQL query text
function extractProcessNames(cql: string): string[] {
  const processNames = new Set<string>();

  // Match .exe references in CQL patterns like FileName=/cmd.exe/, ImageFileName=/\\mimikatz\.exe$/
  const exeMatches = cql.match(/[\w.-]+\.exe/gi);
  if (exeMatches) {
    for (const match of exeMatches) {
      const name = match.toLowerCase();
      if (name.length > 4 && !name.includes('*')) {
        processNames.add(name);
      }
    }
  }

  return [...processNames];
}

// Extract file paths from CQL query text
function extractFilePaths(cql: string): string[] {
  const filePaths = new Set<string>();

  const interestingPaths = [
    'C:\\Windows\\Temp', 'C:\\Windows\\System32', 'C:\\Windows\\SysWOW64',
    'C:\\ProgramData', 'C:\\Users\\Public', '\\AppData\\Local\\Temp',
    '\\AppData\\Roaming',
  ];

  const cqlLower = cql.toLowerCase();
  for (const path of interestingPaths) {
    if (cqlLower.includes(path.toLowerCase())) {
      filePaths.add(path);
    }
  }

  if (cqlLower.includes('\\temp\\') || cqlLower.includes('\\tmp\\')) {
    filePaths.add('Temp directory');
  }

  return [...filePaths];
}

// Extract registry paths from CQL query text
function extractRegistryPaths(cql: string): string[] {
  const registryPaths = new Set<string>();

  const cqlLower = cql.toLowerCase();
  if (cqlLower.includes('hklm') || cqlLower.includes('hkey_local_machine')) {
    registryPaths.add('HKLM registry');
  }
  if (cqlLower.includes('hkcu') || cqlLower.includes('hkey_current_user')) {
    registryPaths.add('HKCU registry');
  }
  if (cqlLower.includes('\\run\\') || cqlLower.includes('\\runonce\\')) {
    registryPaths.add('Run/RunOnce keys');
  }
  if (cqlLower.includes('\\services\\')) {
    registryPaths.add('Services registry');
  }

  return [...registryPaths];
}

// Extract CVE IDs from name and description
function extractCves(text: string): string[] {
  const matches = text.match(/CVE-\d{4}-\d+/gi);
  if (!matches) return [];
  return [...new Set(matches.map(m => m.toUpperCase()))];
}

// Infer platforms from CQL query and log_sources
function extractPlatforms(cql: string, logSources: string[]): string[] {
  const platforms = new Set<string>();

  // Check event_platform in CQL
  if (/event_platform\s*=\s*"?Win/i.test(cql)) platforms.add('windows');
  if (/event_platform\s*=\s*"?Mac/i.test(cql)) platforms.add('macos');
  if (/event_platform\s*=\s*"?Lin/i.test(cql)) platforms.add('linux');

  // Infer from log_sources
  for (const src of logSources) {
    const lower = src.toLowerCase();
    if (lower === 'endpoint') {
      // Endpoint could be any OS; only add if no specific platform found
      if (platforms.size === 0) {
        platforms.add('windows');
        platforms.add('linux');
      }
    } else if (lower === 'network') {
      platforms.add('network');
    } else if (lower === 'cloud' || lower.includes('aws') || lower.includes('azure') || lower.includes('gcp')) {
      platforms.add('cloud');
    }
  }

  return [...platforms];
}

// Map log_sources to asset type
function deriveAssetType(logSources: string[]): string | null {
  if (!logSources || logSources.length === 0) return null;
  const first = logSources[0].toLowerCase();
  if (first === 'endpoint') return 'Endpoint';
  if (first === 'network') return 'Network';
  if (first === 'cloud' || first.includes('aws') || first.includes('azure') || first.includes('gcp')) return 'Cloud';
  if (first === 'identity' || first === 'idp') return 'Endpoint';
  return null;
}

// Map log_sources to security domain
function deriveSecurityDomain(logSources: string[]): string | null {
  if (!logSources || logSources.length === 0) return null;
  const first = logSources[0].toLowerCase();
  if (first === 'endpoint') return 'endpoint';
  if (first === 'network') return 'network';
  if (first === 'cloud' || first.includes('aws') || first.includes('azure') || first.includes('gcp')) return 'cloud';
  if (first === 'identity' || first === 'idp') return 'access';
  return null;
}

// Map tags to detection type
function deriveDetectionType(tags: string[]): string | null {
  for (const tag of tags) {
    const lower = tag.toLowerCase();
    if (lower === 'hunting') return 'Hunting';
    if (lower === 'detection') return 'TTP';
    if (lower === 'anomaly') return 'Anomaly';
    if (lower === 'correlation') return 'Correlation';
  }
  return null;
}

export function parseCqlHubFile(filePath: string): Detection | null {
  try {
    const content = readFileSync(filePath, 'utf-8');
    const rule = parseYaml(content) as CqlHubRule;

    // name and cql are required
    if (!rule.name || !rule.cql) {
      return null;
    }

    const id = generateId(filePath, rule.name);
    const mitreIds = rule.mitre_ids || [];
    const logSources = rule.log_sources || [];
    const tags = rule.tags || [];
    const csModules = rule.cs_required_modules || [];

    // Build description: include explanation if present
    let description = rule.description || '';
    if (rule.explanation) {
      description = description
        ? `${description}\n\n${rule.explanation}`
        : rule.explanation;
    }

    // Combine text fields for CVE extraction
    const combinedText = `${rule.name} ${rule.description || ''}`;

    // Build enriched tags: include cs_required_modules as prefixed tags
    const enrichedTags = [
      ...tags,
      ...csModules.map(m => `cs_module:${m}`),
    ];

    const detection: Detection = {
      id,
      name: rule.name,
      description,
      query: rule.cql,
      source_type: 'crowdstrike_cql',
      mitre_ids: mitreIds,
      logsource_category: logSources.length > 0 ? logSources[0].toLowerCase() : null,
      logsource_product: 'crowdstrike',
      logsource_service: 'falcon_logscale',
      severity: null,
      status: null,
      author: rule.author || null,
      date_created: null,
      date_modified: null,
      references: [],
      falsepositives: [],
      tags: enrichedTags,
      file_path: filePath,
      raw_yaml: content,

      cves: extractCves(combinedText),
      analytic_stories: [],
      data_sources: logSources,
      detection_type: deriveDetectionType(tags),
      asset_type: deriveAssetType(logSources),
      security_domain: deriveSecurityDomain(logSources),
      process_names: extractProcessNames(rule.cql),
      file_paths: extractFilePaths(rule.cql),
      registry_paths: extractRegistryPaths(rule.cql),
      mitre_tactics: extractMitreTactics(mitreIds),
      platforms: extractPlatforms(rule.cql, logSources),
      kql_category: null,
      kql_tags: [],
      kql_keywords: [],
      sublime_attack_types: [],
      sublime_detection_methods: [],
      sublime_tactics: [],
    };

    return detection;
  } catch {
    // Skip files that can't be parsed
    return null;
  }
}
