/**
 * CTI Analyst Node
 * 
 * Extracts TTPs from threat intelligence using an LLM.
 * Maps to MITRE ATT&CK techniques with confidence scores.
 */

import { ChatAnthropic } from '@langchain/anthropic';
import { getConfig } from '../config.js';
import type { PipelineState, Technique } from '../state/types.js';
import { z } from 'zod';

// Zod schema for structured output
const TechniqueSchema = z.object({
  id: z.string().describe('MITRE ATT&CK technique ID (e.g., T1003.001)'),
  name: z.string().describe('Technique name'),
  tactic: z.string().describe('MITRE tactic'),
  confidence: z.number().min(0).max(1).describe('Confidence score 0.0-1.0'),
  context: z.string().describe('Why this technique was identified'),
});

const TechniquesResponseSchema = z.object({
  techniques: z.array(TechniqueSchema).describe('List of extracted MITRE ATT&CK techniques'),
});

const CTI_ANALYST_PROMPT = `You are an elite Cyber Threat Intelligence (CTI) analyst.

Your task is to extract MITRE ATT&CK techniques from the provided threat intelligence.

CRITICAL RULES:
1. Use sub-techniques when available (T1003.001 not just T1003)
2. Map to technique being DETECTED, not the entire attack chain
3. Focus on BEHAVIORS, not IOCs (IPs, hashes are low value)
4. Include confidence score (0.0 - 1.0) based on how clearly the TTP is described
5. Provide context explaining WHY you identified this technique

HIGH VALUE techniques to look for:
- Credential dumping (T1003.*)
- PowerShell execution (T1059.001)
- Lateral movement (T1021.*)
- Persistence mechanisms (T1547.*, T1543.*)
- Defense evasion (T1055.*, T1027.*)

LOW VALUE - skip these unless explicitly detailed:
- Generic reconnaissance
- Specific IP addresses or domains
- File hashes

Analyze this threat intelligence:
`;

export async function ctiAnalystNode(state: PipelineState): Promise<Partial<PipelineState>> {
  console.log('[CTI Analyst] Analyzing threat intelligence...');
  
  const cfg = getConfig();
  
  // Dry-run mode: return mock data without calling the LLM
  if (cfg.dryRun || !cfg.anthropicApiKey) {
    console.log('[CTI Analyst] Dry-run mode - returning mock techniques');
    
    // Parse technique ID from input if it looks like T1234 or T1234.001
    const techMatch = state.input_content.match(/T\d{4}(?:\.\d{3})?/i);
    const mockTechniques: Technique[] = techMatch 
      ? [{
          id: techMatch[0].toUpperCase(),
          name: 'Mock Technique',
          tactic: 'execution',
          confidence: 0.9,
          context: 'Dry-run mode - technique extracted from input'
        }]
      : [{
          id: 'T1059.001',
          name: 'PowerShell',
          tactic: 'execution', 
          confidence: 0.85,
          context: 'Dry-run mode - default mock technique'
        }];
    
    console.log(`[CTI Analyst] Mock extracted ${mockTechniques.length} techniques:`);
    mockTechniques.forEach(t => console.log(`  - ${t.id}: ${t.name} (confidence: ${t.confidence})`));
    
    return {
      techniques: mockTechniques,
      current_step: 'cti_analysis_complete',
      warnings: ['Dry-run mode: using mock data, no LLM call made'],
    };
  }
  
  const model = new ChatAnthropic({
    modelName: cfg.llmModel,
    temperature: 0,
  });

  // Use structured output with Zod schema
  const structuredModel = model.withStructuredOutput(TechniquesResponseSchema);
  const prompt = CTI_ANALYST_PROMPT + state.input_content;
  
  try {
    const response = await structuredModel.invoke(prompt);
    const techniques: Technique[] = response.techniques || [];
    
    console.log(`[CTI Analyst] Extracted ${techniques.length} techniques:`);
    techniques.forEach(t => console.log(`  - ${t.id}: ${t.name} (confidence: ${t.confidence})`));

    return {
      techniques,
      current_step: 'cti_analysis_complete',
    };
  } catch (error) {
    const errorMsg = error instanceof Error ? error.message : 'Unknown error';
    console.error('[CTI Analyst] Error:', errorMsg);
    return {
      techniques: [],
      errors: [errorMsg],
      current_step: 'cti_analysis_failed',
    };
  }
}
