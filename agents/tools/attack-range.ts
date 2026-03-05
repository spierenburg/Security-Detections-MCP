/**
 * Attack Range Tool
 * 
 * Wraps Attack Range CLI for atomic test execution.
 * CRITICAL: Follows the exact workflow from atomic-red-team-testing skill.
 * 
 * Supports:
 * - Standard Atomic Red Team tests
 * - Custom atomics deployment via Ansible
 * - Multiple test execution in sequence
 */

import { promisify } from 'util';
import { exec } from 'child_process';

const execAsync = promisify(exec);

import { getConfig } from '../config.js';

function getAttackRangeConfig() {
  const cfg = getConfig();
  return {
    path: cfg.attackRangePath,
    poetryVenv: cfg.attackRangeVenv,
    defaultTarget: cfg.attackRangeDefaultTarget,
    defaultEngine: cfg.attackRangeEngine,
    customAtomicsPlaybook: cfg.attackRangeCustomPlaybook,
  };
}

// Environment setup required for Attack Range
const ATTACK_RANGE_ENV = {
  ...process.env,
  OBJC_DISABLE_INITIALIZE_FORK_SAFETY: 'YES',
};

export interface AtomicExecutionResult {
  success: boolean;
  technique_id: string;
  test_id?: string;
  output: string;
  exit_code: number;
  error?: string;
}

export interface AttackRangeStatus {
  running: boolean;
  splunk_url?: string;
  windows_target?: string;
  windows_target_2?: string;
  linux_target?: string;
  target_ip?: string;
}

export interface CustomAtomicDeployResult {
  success: boolean;
  output: string;
  deployed_atomics?: string[];
}

export class AttackRangeTool {
  private get config() {
    return getAttackRangeConfig();
  }

  /**
   * Build the shell command with proper venv activation
   */
  private buildCommand(cmd: string): string {
    const parts = [`cd ${this.config.path}`];
    if (this.config.poetryVenv) {
      parts.push(`source ${this.config.poetryVenv}`);
    }
    parts.push(cmd);
    return parts.join(' && ');
  }

  /**
   * Get Attack Range status
   */
  async getStatus(): Promise<AttackRangeStatus> {
    try {
      const cmd = this.buildCommand('python attack_range.py show');
      const { stdout } = await execAsync(cmd, { 
        shell: '/bin/bash',
        env: ATTACK_RANGE_ENV,
        timeout: 60000,
      });
      
      // Parse output to determine status
      const running = stdout.includes('running') && (stdout.includes('ar-win-') || stdout.includes('ar-splunk-'));
      
      // Extract IPs and targets
      const lines = stdout.split('\n');
      let splunkUrl: string | undefined;
      let windowsTarget: string | undefined;
      let windowsTarget2: string | undefined;
      let linuxTarget: string | undefined;
      let targetIp: string | undefined;

      for (const line of lines) {
        if (line.includes('ar-splunk-') && line.includes('running')) {
          const ipMatch = line.match(/(\d+\.\d+\.\d+\.\d+)/);
          if (ipMatch) splunkUrl = `http://${ipMatch[1]}:8000`;
        }
        if (line.includes('ar-win-') && line.includes('-0') && line.includes('running')) {
          const parts = line.trim().split(/\s+/);
          windowsTarget = parts[0];
          const ipMatch = line.match(/(\d+\.\d+\.\d+\.\d+)/);
          if (ipMatch) targetIp = ipMatch[1];
        }
        if (line.includes('ar-win-') && line.includes('-1') && line.includes('running')) {
          const parts = line.trim().split(/\s+/);
          windowsTarget2 = parts[0];
        }
        if (line.includes('ar-linux-') && line.includes('running')) {
          const parts = line.trim().split(/\s+/);
          linuxTarget = parts[0];
        }
      }
      
      return {
        running,
        splunk_url: splunkUrl,
        windows_target: windowsTarget || this.config.defaultTarget,
        windows_target_2: windowsTarget2,
        linux_target: linuxTarget,
        target_ip: targetIp,
      };
    } catch (error) {
      console.error('[Attack Range] Error getting status:', error);
      return { running: false };
    }
  }

  /**
   * Deploy custom atomics via Ansible
   * 
   * Deploys all custom atomics defined in deploy_custom_atomics.yml:
   * - T9999.001 - SHEETCREEP Document Collection
   * - T9999.002 - SHEETCREEP Hidden CMD Process
   * - T9999.003 - SHEETCREEP GitHub Exfiltration
   * - T9999.004 - PDFSIDER Attack Chain
   */
  async deployCustomAtomics(targetIp: string): Promise<CustomAtomicDeployResult> {
    const playbookPath = `${this.config.path}/${this.config.customAtomicsPlaybook}`;
    
    const cmd = this.buildCommand(`ansible-playbook -i '${targetIp},' ${playbookPath}`);

    try {
      console.log(`[Attack Range] Deploying custom atomics to ${targetIp}...`);
      console.log(`[Attack Range] Playbook: ${playbookPath}`);
      
      const { stdout, stderr } = await execAsync(cmd, {
        shell: '/bin/bash',
        env: ATTACK_RANGE_ENV,
        timeout: 180000, // 3 minute timeout for Ansible
      });

      const success = stdout.includes('changed:') || 
                     stdout.includes('ok:') || 
                     stdout.includes('Custom Atomics Deployed Successfully');
      
      // Parse deployed atomics from output
      const deployedAtomics: string[] = [];
      if (stdout.includes('T9999.001')) deployedAtomics.push('T9999.001');
      if (stdout.includes('T9999.002')) deployedAtomics.push('T9999.002');
      if (stdout.includes('T9999.003')) deployedAtomics.push('T9999.003');
      if (stdout.includes('T9999.004')) deployedAtomics.push('T9999.004');
      
      return {
        success,
        output: stdout + (stderr ? `\nSTDERR: ${stderr}` : ''),
        deployed_atomics: deployedAtomics,
      };
    } catch (error) {
      return {
        success: false,
        output: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }

  /**
   * Run an Atomic Red Team test
   * 
   * Works for both standard atomics (T1003.001) and custom atomics (T9999.001)
   */
  async runAtomicTest(
    techniqueId: string,
    target?: string
  ): Promise<AtomicExecutionResult> {
    const targetName = target || this.config.defaultTarget;
    
    // Build command following the skill exactly
    const cmd = this.buildCommand(
      `python attack_range.py simulate -e ${this.config.defaultEngine} -te ${techniqueId} -t ${targetName}`
    );

    try {
      console.log(`[Attack Range] Running atomic test: ${techniqueId}`);
      console.log(`[Attack Range] Target: ${targetName}`);
      
      const { stdout, stderr } = await execAsync(cmd, {
        shell: '/bin/bash',
        env: ATTACK_RANGE_ENV,
        timeout: 600000, // 10 minute timeout for some long-running tests
      });

      // Check for success indicators from the skill
      const success = stdout.includes('Exit code: 0') || 
                     stdout.includes('Done executing test:') ||
                     stdout.includes('changed:') ||
                     stdout.includes('PLAY RECAP') && !stdout.includes('failed=1');

      return {
        success,
        technique_id: techniqueId,
        output: stdout + (stderr ? `\nSTDERR: ${stderr}` : ''),
        exit_code: success ? 0 : 1,
      };
    } catch (error) {
      const errorMsg = error instanceof Error ? error.message : 'Unknown error';
      return {
        success: false,
        technique_id: techniqueId,
        output: '',
        exit_code: 1,
        error: errorMsg,
      };
    }
  }

  /**
   * Run multiple atomic tests in sequence
   * 
   * Per the skill: Can run multiple atomics, just execute sequentially
   */
  async runMultipleAtomicTests(
    techniqueIds: string[],
    target?: string
  ): Promise<AtomicExecutionResult[]> {
    const results: AtomicExecutionResult[] = [];
    
    for (const techniqueId of techniqueIds) {
      const result = await this.runAtomicTest(techniqueId, target);
      results.push(result);
      
      // Small delay between tests
      await new Promise(resolve => setTimeout(resolve, 2000));
    }
    
    return results;
  }

  /**
   * Wait for log ingestion into Splunk
   * Per the skill: Wait 2-3 minutes for Splunk indexing
   */
  async waitForIngestion(seconds: number = 120): Promise<void> {
    console.log(`[Attack Range] Waiting ${seconds}s for Splunk log ingestion...`);
    await new Promise(resolve => setTimeout(resolve, seconds * 1000));
    console.log(`[Attack Range] Ingestion wait complete`);
  }

  /**
   * Execute custom atomic playbook with execution (not just deployment)
   * Uses custom_sheetcreep_atomic.yml which deploys AND executes
   */
  async runCustomAtomicPlaybook(targetIp: string, playbook: string = 'custom_sheetcreep_atomic.yml'): Promise<CustomAtomicDeployResult> {
    const playbookPath = `${this.config.path}/${playbook}`;
    
    const cmd = this.buildCommand(`ansible-playbook -i '${targetIp},' ${playbookPath}`);

    try {
      console.log(`[Attack Range] Running custom atomic playbook: ${playbook}`);
      console.log(`[Attack Range] Target: ${targetIp}`);
      
      const { stdout, stderr } = await execAsync(cmd, {
        shell: '/bin/bash',
        env: ATTACK_RANGE_ENV,
        timeout: 600000, // 10 minute timeout
      });

      const success = stdout.includes('SHEETCREEP Custom Atomic Tests Complete') ||
                     stdout.includes('changed:') ||
                     (stdout.includes('ok:') && !stdout.includes('failed=1'));
      
      return {
        success,
        output: stdout + (stderr ? `\nSTDERR: ${stderr}` : ''),
      };
    } catch (error) {
      return {
        success: false,
        output: error instanceof Error ? error.message : 'Unknown error',
      };
    }
  }
}

// Singleton
let tool: AttackRangeTool | null = null;

export function getAttackRangeTool(): AttackRangeTool {
  if (!tool) {
    tool = new AttackRangeTool();
  }
  return tool;
}
