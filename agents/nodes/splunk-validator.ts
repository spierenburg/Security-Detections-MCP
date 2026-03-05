/**
 * Splunk Validator Node
 * 
 * Validates detections by running them against Splunk via the Splunk MCP.
 * Uses the run_detection tool which executes SPL directly from detection YAML files.
 */

import { getMCPClient } from '../tools/mcp-client.js';
import type { PipelineState, Detection } from '../state/types.js';

async function callSplunkMCP(toolName: string, args: Record<string, unknown>): Promise<any> {
  const client = getMCPClient();
  const result = await client.callTool({
    server: 'splunk-mcp',
    tool: toolName,
    arguments: args,
  });
  if (!result.success) {
    throw new Error(result.error || 'Splunk MCP call failed');
  }
  return result.result;
}

/**
 * Run a detection YAML file via Splunk MCP's run_detection tool
 */
async function runDetection(detectionPath: string): Promise<{
  success: boolean;
  count: number;
  results?: any[];
  error?: string;
}> {
  try {
    // Use the run_detection tool from Splunk MCP
    // This tool reads the YAML, extracts the search, and runs it
    const result = await callSplunkMCP('run_detection', {
      detection_path: detectionPath,
      auto_prefix: true,  // Prepends 'search ' if needed
    });
    
    // Parse results
    if (result && result.results) {
      return {
        success: true,
        count: result.results.length || 0,
        results: result.results,
      };
    }
    
    // pending / dry-run mode
    if (result && (result._mcp_pending || result._dry_run)) {
      console.log(`[Splunk Validator] MCP call pending – pipeline will continue with 0 events`);
      return {
        success: true,
        count: 0,
        error: 'MCP not connected – call structure logged',
      };
    }
    
    return {
      success: true,
      count: 0,
    };
    
  } catch (error) {
    return {
      success: false,
      count: 0,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Run a raw SPL search via Splunk MCP
 */
async function runSearch(spl: string): Promise<{
  success: boolean;
  count: number;
  results?: any[];
  error?: string;
}> {
  try {
    // Use the search tool from Splunk MCP
    const result = await callSplunkMCP('search', {
      search: spl,
    });
    
    if (result && result.results) {
      return {
        success: true,
        count: result.results.length || 0,
        results: result.results,
      };
    }
    
    return {
      success: true,
      count: 0,
    };
    
  } catch (error) {
    return {
      success: false,
      count: 0,
      error: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

export async function splunkValidatorNode(state: PipelineState): Promise<Partial<PipelineState>> {
  console.log('[Splunk Validator] Validating detections via Splunk MCP...');
  
  const { getConfig } = await import('../config.js');
  const cfg = getConfig();
  
  // Dry-run mode: return mock validation results
  if (cfg.dryRun) {
    console.log('[Splunk Validator] Dry-run mode - returning mock validation results');
    const mockDetections = state.detections.map(d => ({
      ...d,
      status: 'validated' as const,
      validation_result: {
        passed: true,
        event_count: 5,
      },
    }));
    
    console.log(`[Splunk Validator] Mock validated ${mockDetections.length} detection(s)`);
    
    return {
      detections: mockDetections,
      current_step: 'splunk_validation_complete',
      warnings: ['Dry-run mode: no actual Splunk validation performed'],
    };
  }
  
  // Only validate detections that have completed atomic tests
  const completedAtomics = new Set(
    state.atomic_tests
      .filter(t => t.execution_status === 'completed')
      .map(t => t.technique_id)
  );
  
  const detectionsToValidate = state.detections.filter(
    d => completedAtomics.has(d.technique_id) && d.status === 'draft'
  );
  
  if (detectionsToValidate.length === 0) {
    console.log('[Splunk Validator] No detections ready for validation');
    return { current_step: 'splunk_validation_complete' };
  }

  const updatedDetections: Detection[] = [];

  for (const detection of detectionsToValidate) {
    try {
      console.log(`[Splunk Validator] Validating: ${detection.name}`);
      console.log(`[Splunk Validator] Detection path: ${detection.file_path}`);
      
      // Use run_detection which handles the YAML parsing for us
      const result = await runDetection(detection.file_path);
      
      if (result.success && result.count > 0) {
        console.log(`[Splunk Validator] ✓ ${detection.name}: ${result.count} events matched`);
        updatedDetections.push({
          ...detection,
          status: 'validated',
          validation_result: {
            passed: true,
            event_count: result.count,
          },
        });
      } else if (result.success && result.count === 0) {
        console.log(`[Splunk Validator] ✗ ${detection.name}: No events matched`);
        
        // If no results, try a simpler query to check if data exists at all
        const checkQuery = `search index=* earliest=-15m | head 1 | stats count`;
        const checkResult = await runSearch(checkQuery);
        
        if (checkResult.count === 0) {
          console.log(`[Splunk Validator] Warning: No data in Splunk at all - may need more ingestion time`);
        }
        
        updatedDetections.push({
          ...detection,
          status: 'failed',
          validation_result: {
            passed: false,
            event_count: 0,
            error: result.error || 'Detection did not fire - no matching events',
          },
        });
      } else {
        console.log(`[Splunk Validator] ✗ ${detection.name}: Query failed - ${result.error}`);
        updatedDetections.push({
          ...detection,
          status: 'failed',
          validation_result: {
            passed: false,
            event_count: 0,
            error: result.error,
          },
        });
      }

    } catch (error) {
      console.error(`[Splunk Validator] Error validating ${detection.name}:`, error);
      updatedDetections.push({
        ...detection,
        status: 'failed',
        validation_result: {
          passed: false,
          event_count: 0,
          error: error instanceof Error ? error.message : 'Unknown error',
        },
      });
    }
  }

  // Merge with existing detections
  const allDetections = state.detections.map(d => {
    const updated = updatedDetections.find(u => u.id === d.id);
    return updated || d;
  });

  const validatedCount = updatedDetections.filter(d => d.status === 'validated').length;
  const failedCount = updatedDetections.filter(d => d.status === 'failed').length;
  
  console.log(`[Splunk Validator] Results: ${validatedCount} validated, ${failedCount} failed`);

  return {
    detections: allDetections,
    current_step: 'splunk_validation_complete',
  };
}
