/**
 * Detection Agents - Main Entry Point
 * 
 * Exports the LangGraph pipeline and tools for use:
 * - CLI: tsx src/cli.ts orchestrate --url <url>
 * - API: import { runDetectionPipeline } from 'detection-agents'
 * - Cursor: Invoked via subagents that wrap this
 */

export { 
  runDetectionPipeline, 
  createDetectionPipeline,
  createInitialState,
} from '../graphs/detection-pipeline.js';

export type { PipelineState } from '../state/types.js';

export { getMCPClient } from '../tools/mcp-client.js';
export { getAttackRangeTool } from '../tools/attack-range.js';

// Node exports for custom pipelines
export { ctiAnalystNode } from '../nodes/cti-analyst.js';
export { coverageAnalyzerNode } from '../nodes/coverage-analyzer.js';
export { detectionEngineerNode } from '../nodes/detection-engineer.js';
export { qaReviewerNode } from '../nodes/qa-reviewer.js';
export { fpAnalystNode } from '../nodes/fp-analyst.js';
export { atomicExecutorNode } from '../nodes/atomic-executor.js';
export { siemValidatorNode } from '../nodes/siem-validator.js';
export { splunkValidatorNode } from '../nodes/splunk-validator.js';
export { dataDumperNode } from '../nodes/data-dumper.js';
export { prStagerNode } from '../nodes/pr-stager.js';
export { verifierNode } from '../nodes/verifier.js';
export { 
  attackRangeBuilderNode,
  getRangeStatus,
  analyzeRequiredInfra,
  checkRangeMeetsRequirements,
} from '../nodes/attack-range-builder.js';

// MCP convenience functions
export { splunkSearch, splunkRunDetection, splunkExportDump } from '../tools/mcp-client.js';
