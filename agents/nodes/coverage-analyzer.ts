/**
 * Coverage Analyzer Node
 * 
 * Checks existing detection coverage for extracted techniques
 * and identifies gaps that need new detections.
 */

import { getMCPClient } from '../tools/mcp-client.js';
import type { PipelineState, Gap, Technique } from '../state/types.js';

// Data sources available in Attack Range (per the atomic testing skill)
const ATTACK_RANGE_DATA_SOURCES = [
  'Sysmon',
  'Windows Event Log Security 4688',
  'PowerShell',
  'Sysmon for Linux',
  'Zeek',
];

export async function coverageAnalyzerNode(state: PipelineState): Promise<Partial<PipelineState>> {
  console.log('[Coverage Analyzer] Checking existing coverage...');
  
  const client = getMCPClient();
  const gaps: Gap[] = [];
  
  for (const technique of state.techniques) {
    try {
      // Check if we have detections for this technique
      const result = await client.callTool({
        server: 'security-detections',
        tool: 'list_by_mitre',
        arguments: { technique_id: technique.id },
      });

      if (!result.success) {
        console.log(`[Coverage Analyzer] Error checking ${technique.id}: ${result.error}`);
        continue;
      }

      const existingDetections = result.result as any[];
      const coverageCount = existingDetections?.length || 0;

      console.log(`[Coverage Analyzer] ${technique.id}: ${coverageCount} existing detection(s)`);

      // Determine if this is a gap
      if (coverageCount === 0) {
        // No coverage - high priority
        gaps.push({
          technique_id: technique.id,
          technique_name: technique.name,
          priority: 'high',
          reason: 'No existing detection coverage',
          existing_coverage: 0,
          data_source_available: isDataSourceAvailable(technique.id),
        });
      } else if (coverageCount === 1 && technique.confidence >= 0.8) {
        // Only one detection for high-confidence technique - medium priority
        gaps.push({
          technique_id: technique.id,
          technique_name: technique.name,
          priority: 'medium',
          reason: 'High-confidence technique with minimal coverage',
          existing_coverage: coverageCount,
          data_source_available: isDataSourceAvailable(technique.id),
        });
      }
      // low priority would be for sub-technique coverage gaps, etc.

    } catch (error) {
      console.error(`[Coverage Analyzer] Error processing ${technique.id}:`, error);
    }
  }

  // Sort by priority
  gaps.sort((a, b) => a.priority.localeCompare(b.priority));

  console.log(`[Coverage Analyzer] Identified ${gaps.length} gap(s):`);
  gaps.forEach(g => console.log(`  - ${g.priority}: ${g.technique_id} - ${g.reason}`));

  return {
    gaps,
    current_step: 'coverage_analysis_complete',
  };
}

/**
 * Check if we have data sources in Attack Range to detect this technique
 */
function isDataSourceAvailable(techniqueId: string): boolean {
  // Map common techniques to their data source requirements
  const techniqueDataSources: Record<string, string[]> = {
    'T1003.001': ['Sysmon'],  // LSASS dumping - Sysmon EventID 10
    'T1003.002': ['Windows Event Log Security 4688'],  // SAM
    'T1059.001': ['PowerShell', 'Sysmon'],  // PowerShell
    'T1059.003': ['Sysmon'],  // Windows Command Shell
    'T1021.001': ['Windows Event Log Security 4688'],  // RDP
    'T1021.002': ['Windows Event Log Security 4688'],  // SMB
    'T1547.001': ['Sysmon'],  // Registry Run Keys
    'T1543.003': ['Sysmon'],  // Windows Service
    'T1055': ['Sysmon'],  // Process Injection
    'T1027': ['Sysmon', 'PowerShell'],  // Obfuscation
    'T1119': ['PowerShell', 'Sysmon'],  // Automated Collection
    'T1074.001': ['Sysmon'],  // Local Data Staging
  };

  // Check base technique if sub-technique not found
  const baseId = techniqueId.split('.')[0];
  const requiredSources = techniqueDataSources[techniqueId] || techniqueDataSources[baseId] || [];
  
  // If no specific requirement, assume available
  if (requiredSources.length === 0) {
    return true;
  }

  // Check if any required source is available
  return requiredSources.some(src => ATTACK_RANGE_DATA_SOURCES.includes(src));
}
