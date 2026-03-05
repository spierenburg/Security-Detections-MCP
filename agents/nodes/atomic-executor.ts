/**
 * Atomic Executor Node
 * 
 * Executes Atomic Red Team tests for created detections.
 * CRITICAL: Follows the exact workflow from atomic-red-team-testing skill.
 * 
 * Supports:
 * 1. Standard Atomic Red Team tests (T1003.001, T1059.001, etc.)
 * 2. Custom atomics via Ansible deployment (T9999.001-T9999.004, etc.)
 * 3. Running multiple tests in sequence
 * 
 * Key points from the skill:
 * - Always activate Poetry venv before Attack Range commands
 * - Deploy custom atomics via Ansible BEFORE running them
 * - Wait 2-3 minutes for Splunk log ingestion
 */

import { getAttackRangeTool } from '../tools/attack-range.js';
import type { PipelineState, AtomicTest, Detection } from '../state/types.js';

// Map of technique IDs to their standard Atomic Red Team test availability
const STANDARD_ATOMICS: Record<string, boolean> = {
  'T1003.001': true,   // LSASS Memory
  'T1003.002': true,   // Security Account Manager
  'T1059.001': true,   // PowerShell
  'T1059.003': true,   // Windows Command Shell
  'T1059.007': true,   // JavaScript
  'T1021.001': true,   // Remote Desktop Protocol
  'T1021.002': true,   // SMB/Windows Admin Shares
  'T1547.001': true,   // Registry Run Keys
  'T1543.003': true,   // Windows Service
  'T1055': true,       // Process Injection
  'T1027': true,       // Obfuscated Files or Information
  'T1119': true,       // Automated Collection
  'T1074.001': true,   // Local Data Staging
  'T1574.002': true,   // DLL Side-Loading
  'T1219': true,       // Remote Access Software
  'T1486': true,       // Data Encrypted for Impact
  'T1621': true,       // MFA Request Generation
  'T1567.002': true,   // Exfiltration to Cloud Storage
  'T1564.003': true,   // Hidden Window
  'T1497': true,       // Virtualization/Sandbox Evasion
};

// Custom atomics available in deploy_custom_atomics.yml
const CUSTOM_ATOMICS: Record<string, { name: string; description: string }> = {
  'T9999.001': { name: 'SHEETCREEP Document Collection', description: 'PowerShell document collection with staging' },
  'T9999.002': { name: 'SHEETCREEP Hidden CMD', description: 'Hidden cmd.exe with redirected I/O' },
  'T9999.003': { name: 'SHEETCREEP GitHub Exfil', description: 'Document exfiltration to GitHub' },
  'T9999.004': { name: 'PDFSIDER Attack Chain', description: 'Anti-VM, debugger check, hidden cmd, C2' },
};

// Mapping from detection behavior to custom atomics
const BEHAVIOR_TO_CUSTOM_ATOMIC: Record<string, string> = {
  'document_collection': 'T9999.001',
  'automated_collection': 'T9999.001',
  'hidden_cmd': 'T9999.002',
  'hidden_process': 'T9999.002',
  'github_exfiltration': 'T9999.003',
  'github_exfil': 'T9999.003',
  'anti_vm': 'T9999.004',
  'debugger_check': 'T9999.004',
  'pdfsider': 'T9999.004',
  'sheetcreep': 'T9999.001',
};

export async function atomicExecutorNode(state: PipelineState): Promise<Partial<PipelineState>> {
  console.log('[Atomic Executor] Preparing atomic tests for validation...');
  
  const { getConfig } = await import('../config.js');
  const cfg = getConfig();
  
  // Dry-run mode: return mock test results
  if (cfg.dryRun) {
    console.log('[Atomic Executor] Dry-run mode - returning mock test results');
    const mockTests: AtomicTest[] = state.detections.map(d => ({
      technique_id: d.technique_id,
      test_name: `Mock atomic test for ${d.technique_id}`,
      execution_status: 'completed' as const,
      output: 'Dry-run mode: no actual test executed',
    }));
    
    console.log(`[Atomic Executor] Mock completed ${mockTests.length} test(s)`);
    
    return {
      atomic_tests: mockTests,
      current_step: 'atomic_execution_complete',
      warnings: ['Dry-run mode: no atomic tests actually executed'],
    };
  }
  
  const tool = getAttackRangeTool();
  const atomicTests: AtomicTest[] = [];
  
  // Check Attack Range status first
  const status = await tool.getStatus();
  if (!status.running) {
    console.log('[Atomic Executor] Attack Range is not running!');
    return {
      errors: ['Attack Range is not running. Start it with: python attack_range.py build'],
      current_step: 'atomic_execution_failed',
    };
  }
  
  console.log(`[Atomic Executor] Attack Range status:`);
  console.log(`  - Splunk: ${status.splunk_url}`);
  console.log(`  - Windows Target: ${status.windows_target}`);
  console.log(`  - Target IP: ${status.target_ip}`);

  // Collect all technique IDs and determine which atomics to run
  const standardAtomicsToRun: string[] = [];
  const customAtomicsToRun: string[] = [];
  const detectionToAtomic: Map<string, string> = new Map();

  for (const detection of state.detections) {
    const techniqueId = detection.technique_id;
    const hasStandardAtomic = STANDARD_ATOMICS[techniqueId] || STANDARD_ATOMICS[techniqueId.split('.')[0]];
    
    // Check if this detection needs a custom atomic based on its behavior
    const detectionNameLower = detection.name.toLowerCase();
    let customAtomicId: string | undefined;
    
    for (const [behavior, atomicId] of Object.entries(BEHAVIOR_TO_CUSTOM_ATOMIC)) {
      if (detectionNameLower.includes(behavior.replace('_', ' ')) || 
          detectionNameLower.includes(behavior.replace('_', '_'))) {
        customAtomicId = atomicId;
        break;
      }
    }

    if (customAtomicId && !customAtomicsToRun.includes(customAtomicId)) {
      customAtomicsToRun.push(customAtomicId);
      detectionToAtomic.set(detection.name, customAtomicId);
      console.log(`[Atomic Executor] Detection "${detection.name}" → Custom atomic ${customAtomicId}`);
    } else if (hasStandardAtomic && !standardAtomicsToRun.includes(techniqueId)) {
      standardAtomicsToRun.push(techniqueId);
      detectionToAtomic.set(detection.name, techniqueId);
      console.log(`[Atomic Executor] Detection "${detection.name}" → Standard atomic ${techniqueId}`);
    } else {
      console.log(`[Atomic Executor] No atomic available for "${detection.name}" (${techniqueId})`);
      atomicTests.push({
        technique_id: techniqueId,
        test_name: `No atomic test available for ${techniqueId}`,
        execution_status: 'pending',
      });
    }
  }

  // Deploy custom atomics if needed
  if (customAtomicsToRun.length > 0 && status.target_ip) {
    console.log(`[Atomic Executor] Deploying custom atomics to ${status.target_ip}...`);
    const deployResult = await tool.deployCustomAtomics(status.target_ip);
    if (deployResult.success) {
      console.log('[Atomic Executor] ✓ Custom atomics deployed successfully');
    } else {
      console.log('[Atomic Executor] ✗ Custom atomic deployment failed:', deployResult.output);
    }
  }

  // Run standard atomics
  console.log(`[Atomic Executor] Running ${standardAtomicsToRun.length} standard atomics...`);
  for (const techniqueId of standardAtomicsToRun) {
    try {
      console.log(`[Atomic Executor] Running standard atomic: ${techniqueId}`);
      
      const result = await tool.runAtomicTest(techniqueId, status.windows_target);
      
      atomicTests.push({
        technique_id: techniqueId,
        test_name: `Standard Atomic Red Team test for ${techniqueId}`,
        execution_status: result.success ? 'completed' : 'failed',
        output: result.output,
      });

      if (result.success) {
        console.log(`[Atomic Executor] ✓ ${techniqueId} completed`);
      } else {
        console.log(`[Atomic Executor] ✗ ${techniqueId} failed: ${result.error || 'Unknown error'}`);
      }

    } catch (error) {
      console.error(`[Atomic Executor] Error running atomic for ${techniqueId}:`, error);
      atomicTests.push({
        technique_id: techniqueId,
        test_name: `Standard Atomic Red Team test for ${techniqueId}`,
        execution_status: 'failed',
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  // Run custom atomics
  console.log(`[Atomic Executor] Running ${customAtomicsToRun.length} custom atomics...`);
  for (const customId of customAtomicsToRun) {
    const customInfo = CUSTOM_ATOMICS[customId];
    try {
      console.log(`[Atomic Executor] Running custom atomic: ${customId} (${customInfo?.name || 'Unknown'})`);
      
      const result = await tool.runAtomicTest(customId, status.windows_target);
      
      atomicTests.push({
        technique_id: customId,
        test_name: customInfo?.name || `Custom atomic ${customId}`,
        execution_status: result.success ? 'completed' : 'failed',
        output: result.output,
      });

      if (result.success) {
        console.log(`[Atomic Executor] ✓ ${customId} (${customInfo?.name}) completed`);
      } else {
        console.log(`[Atomic Executor] ✗ ${customId} failed: ${result.error || 'Unknown error'}`);
      }

    } catch (error) {
      console.error(`[Atomic Executor] Error running custom atomic ${customId}:`, error);
      atomicTests.push({
        technique_id: customId,
        test_name: customInfo?.name || `Custom atomic ${customId}`,
        execution_status: 'failed',
        error: error instanceof Error ? error.message : 'Unknown error',
      });
    }
  }

  // Wait for log ingestion (per the skill: 2-3 minutes)
  const successfulTests = atomicTests.filter(t => t.execution_status === 'completed');
  if (successfulTests.length > 0) {
    console.log(`[Atomic Executor] ${successfulTests.length} tests completed successfully`);
    console.log('[Atomic Executor] Waiting for Splunk log ingestion (120s)...');
    await tool.waitForIngestion(120);
    console.log('[Atomic Executor] Ingestion wait complete');
  }

  // Summary
  const completed = atomicTests.filter(t => t.execution_status === 'completed').length;
  const failed = atomicTests.filter(t => t.execution_status === 'failed').length;
  const pending = atomicTests.filter(t => t.execution_status === 'pending').length;
  
  console.log(`[Atomic Executor] Summary: ${completed} completed, ${failed} failed, ${pending} pending`);

  return {
    atomic_tests: atomicTests,
    current_step: completed > 0 ? 'atomic_execution_complete' : 'atomic_execution_failed',
  };
}
