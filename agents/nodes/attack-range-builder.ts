/**
 * Attack Range Builder Node
 * 
 * Dynamically configures and builds Attack Range environments based on
 * detection data source requirements.
 * 
 * Key capabilities:
 * - Analyze detection data sources to determine required infrastructure
 * - Generate Attack Range configuration YAML
 * - Build ranges in background (handles long build times)
 * - Poll for build completion
 */

import { promisify } from 'util';
import { exec } from 'child_process';
import * as fs from 'fs';
import * as yaml from 'js-yaml';
import type { PipelineState, Detection } from '../state/types.js';
import { getConfig } from '../config.js';

const execAsync = promisify(exec);

function getAttackRangePaths() {
  const cfg = getConfig();
  return {
    ATTACK_RANGE_PATH: cfg.attackRangePath,
    CONFIG_PATH: `${cfg.attackRangePath}/attack_range.yml`,
    POETRY_VENV: cfg.attackRangeVenv,
  };
}

// Environment for Attack Range commands
const AR_ENV = {
  ...process.env,
  OBJC_DISABLE_INITIALIZE_FORK_SAFETY: 'YES',
};

// Data source to infrastructure mapping
const DATA_SOURCE_MAP: Record<string, string[]> = {
  // Windows sources
  'Sysmon': ['windows_servers'],
  'Windows Event Log': ['windows_servers'],
  'Windows Security': ['windows_servers'],
  'PowerShell': ['windows_servers'],
  'Windows Defender': ['windows_servers'],
  
  // Linux sources
  'Sysmon for Linux': ['linux_servers'],
  'Linux Syslog': ['linux_servers'],
  'Linux Audit': ['linux_servers'],
  
  // Network sources
  'Zeek': ['zeek_server'],
  'Network Traffic': ['zeek_server'],
  'DNS': ['zeek_server'],
  
  // IDS
  'Snort': ['snort_server'],
  'IDS': ['snort_server'],
  
  // Web/Proxy
  'Nginx': ['nginx_server'],
  'Web Proxy': ['nginx_server'],
  'HTTP': ['nginx_server'],
  
  // Active Directory
  'Active Directory': ['windows_servers_domain'],
  'LDAP': ['windows_servers_domain'],
  'Kerberos': ['windows_servers_domain'],
  
  // Cloud
  'AWS CloudTrail': ['aws_cloudtrail'],
  'Azure Activity': ['azure_logging'],
};

interface AttackRangeConfig {
  general: {
    cloud_provider: string;
    attack_range_password: string;
    key_name: string;
    ip_whitelist: string;
    attack_range_name: string;
  };
  aws?: {
    region: string;
    private_key_path: string;
    cloudtrail?: string;
  };
  windows_servers?: Array<{
    hostname: string;
    windows_image: string;
    create_domain?: string;
    join_domain?: string;
  }>;
  linux_servers?: Array<{
    hostname: string;
    sysmon_config?: string;
  }>;
  zeek_server?: { zeek_server: string };
  snort_server?: { snort_server: string };
  nginx_server?: { nginx_server: string };
  kali_server?: { kali_server: string };
}

interface RangeStatus {
  running: boolean;
  windows_targets: string[];
  linux_targets: string[];
  splunk_url?: string;
  has_zeek: boolean;
  has_domain: boolean;
}

/**
 * Build shell command with proper venv activation
 */
function buildCommand(cmd: string): string {
  const { ATTACK_RANGE_PATH, POETRY_VENV } = getAttackRangePaths();
  const activate = POETRY_VENV ? `source ${POETRY_VENV} && ` : '';
  return `cd ${ATTACK_RANGE_PATH} && ${activate}${cmd}`;
}

/**
 * Get current Attack Range status
 */
async function getRangeStatus(): Promise<RangeStatus> {
  try {
    const { stdout } = await execAsync(buildCommand('python attack_range.py show'), {
      shell: '/bin/bash',
      env: AR_ENV,
      timeout: 60000,
    });

    const windows_targets: string[] = [];
    const linux_targets: string[] = [];
    let splunk_url: string | undefined;
    let has_zeek = false;
    let has_domain = false;

    const lines = stdout.split('\n');
    for (const line of lines) {
      if (line.includes('ar-win-') && line.includes('running')) {
        const match = line.match(/(ar-win-[\w-]+)/);
        if (match) windows_targets.push(match[1]);
        if (line.includes('-dc') || line.includes('domain')) has_domain = true;
      }
      if (line.includes('ar-linux-') && line.includes('running')) {
        const match = line.match(/(ar-linux-[\w-]+)/);
        if (match) linux_targets.push(match[1]);
      }
      if (line.includes('ar-splunk-') && line.includes('running')) {
        const ipMatch = line.match(/(\d+\.\d+\.\d+\.\d+)/);
        if (ipMatch) splunk_url = `http://${ipMatch[1]}:8000`;
      }
      if (line.includes('ar-zeek-') && line.includes('running')) {
        has_zeek = true;
      }
    }

    return {
      running: windows_targets.length > 0 || linux_targets.length > 0,
      windows_targets,
      linux_targets,
      splunk_url,
      has_zeek,
      has_domain,
    };
  } catch (error) {
    return {
      running: false,
      windows_targets: [],
      linux_targets: [],
      has_zeek: false,
      has_domain: false,
    };
  }
}

/**
 * Analyze detections to determine required infrastructure
 */
function analyzeRequiredInfra(detections: Detection[]): Set<string> {
  const required = new Set<string>();

  for (const detection of detections) {
    // Check data_source field (can be string or string[])
    const dataSources = detection.data_source || [];
    const sourceList = Array.isArray(dataSources) ? dataSources : [dataSources];
    
    for (const ds of sourceList) {
      for (const [source, infra] of Object.entries(DATA_SOURCE_MAP)) {
        if (ds.toLowerCase().includes(source.toLowerCase())) {
          infra.forEach(i => required.add(i));
        }
      }
    }

    // Check security_domain
    if (detection.security_domain === 'network') {
      required.add('zeek_server');
    }

    // Check asset_type
    const assetType = detection.asset_type?.toLowerCase() || '';
    if (assetType.includes('linux')) {
      required.add('linux_servers');
    }
    if (assetType.includes('windows') || assetType.includes('endpoint')) {
      required.add('windows_servers');
    }
    if (assetType.includes('domain')) {
      required.add('windows_servers_domain');
    }
  }

  return required;
}

/**
 * Check if current range meets requirements
 */
function checkRangeMeetsRequirements(status: RangeStatus, required: Set<string>): {
  meets: boolean;
  missing: string[];
} {
  const missing: string[] = [];

  if (required.has('windows_servers') && status.windows_targets.length === 0) {
    missing.push('Windows server');
  }
  if (required.has('linux_servers') && status.linux_targets.length === 0) {
    missing.push('Linux server');
  }
  if (required.has('zeek_server') && !status.has_zeek) {
    missing.push('Zeek server');
  }
  if (required.has('windows_servers_domain') && !status.has_domain) {
    missing.push('Domain Controller');
  }

  return {
    meets: missing.length === 0,
    missing,
  };
}

/**
 * Generate Attack Range configuration based on requirements
 */
function generateConfig(required: Set<string>): AttackRangeConfig {
  const cfg = getConfig();
  const config: AttackRangeConfig = {
    general: {
      cloud_provider: cfg.attackRangeEngine || 'aws',
      attack_range_password: process.env.ATTACK_RANGE_PASSWORD || 'Pl3aseChang3Me!',
      key_name: process.env.ATTACK_RANGE_KEY_NAME || 'attack-range-key',
      ip_whitelist: process.env.ATTACK_RANGE_IP_WHITELIST || '0.0.0.0/0',
      attack_range_name: 'auto-built',
    },
    aws: {
      region: process.env.AWS_REGION || 'us-west-2',
      private_key_path: process.env.ATTACK_RANGE_PRIVATE_KEY || '~/.ssh/id_rsa',
    },
  };

  // Windows servers
  if (required.has('windows_servers') || required.has('windows_servers_domain')) {
    config.windows_servers = [];
    
    if (required.has('windows_servers_domain')) {
      config.windows_servers.push({
        hostname: 'ar-win-dc',
        windows_image: 'windows-server-2022',
        create_domain: '1',
      });
      config.windows_servers.push({
        hostname: 'ar-win-01',
        windows_image: 'windows-server-2022',
        join_domain: '1',
      });
    } else {
      config.windows_servers.push({
        hostname: 'ar-win',
        windows_image: 'windows-server-2022',
      });
    }
  }

  // Linux servers
  if (required.has('linux_servers')) {
    config.linux_servers = [{
      hostname: 'ar-linux',
      sysmon_config: 'SysMonLinux-CatchAll.xml',
    }];
  }

  // Zeek
  if (required.has('zeek_server')) {
    config.zeek_server = { zeek_server: '1' };
  }

  // Snort
  if (required.has('snort_server')) {
    config.snort_server = { snort_server: '1' };
  }

  // Nginx
  if (required.has('nginx_server')) {
    config.nginx_server = { nginx_server: '1' };
  }

  return config;
}

/**
 * Write configuration to file
 */
async function writeConfig(config: AttackRangeConfig): Promise<void> {
  const { CONFIG_PATH } = getAttackRangePaths();
  const yamlContent = yaml.dump(config);
  fs.writeFileSync(CONFIG_PATH, yamlContent);
  console.log('[Attack Range Builder] Configuration written to:', CONFIG_PATH);
}

/**
 * Start Attack Range build (background)
 */
async function startBuild(): Promise<{ success: boolean; message: string }> {
  try {
    // Run build in background
    const cmd = buildCommand('nohup python attack_range.py build > build.log 2>&1 &');
    await execAsync(cmd, {
      shell: '/bin/bash',
      env: AR_ENV,
    });

    return {
      success: true,
      message: 'Build started in background. This will take 15-30 minutes.',
    };
  } catch (error) {
    return {
      success: false,
      message: error instanceof Error ? error.message : 'Unknown error',
    };
  }
}

/**
 * Main node function
 */
export async function attackRangeBuilderNode(state: PipelineState): Promise<Partial<PipelineState>> {
  console.log('[Attack Range Builder] Analyzing detection requirements...');

  // Get current range status
  const status = await getRangeStatus();
  console.log(`[Attack Range Builder] Current status: ${status.running ? 'Running' : 'Not running'}`);
  console.log(`[Attack Range Builder]   Windows targets: ${status.windows_targets.join(', ') || 'none'}`);
  console.log(`[Attack Range Builder]   Linux targets: ${status.linux_targets.join(', ') || 'none'}`);
  console.log(`[Attack Range Builder]   Zeek: ${status.has_zeek}`);
  console.log(`[Attack Range Builder]   Domain: ${status.has_domain}`);

  // Analyze requirements from detections
  const required = analyzeRequiredInfra(state.detections);
  console.log(`[Attack Range Builder] Required infrastructure: ${Array.from(required).join(', ')}`);

  // Check if current range meets requirements
  const check = checkRangeMeetsRequirements(status, required);

  if (check.meets) {
    console.log('[Attack Range Builder] ✓ Current range meets all requirements');
    return {
      current_step: 'attack_range_ready',
    };
  }

  console.log(`[Attack Range Builder] ✗ Missing infrastructure: ${check.missing.join(', ')}`);
  console.log('[Attack Range Builder] Generating new configuration...');

  // Generate new config
  const newConfig = generateConfig(required);
  
  // For now, just report what would be needed
  // In production, this would actually write config and trigger build
  const configSummary = {
    windows_servers: newConfig.windows_servers?.length || 0,
    linux_servers: newConfig.linux_servers?.length || 0,
    zeek: newConfig.zeek_server?.zeek_server === '1',
    snort: newConfig.snort_server?.snort_server === '1',
    nginx: newConfig.nginx_server?.nginx_server === '1',
  };

  console.log('[Attack Range Builder] Proposed configuration:');
  console.log(`  - Windows servers: ${configSummary.windows_servers}`);
  console.log(`  - Linux servers: ${configSummary.linux_servers}`);
  console.log(`  - Zeek: ${configSummary.zeek}`);
  console.log(`  - Snort: ${configSummary.snort}`);
  console.log(`  - Nginx: ${configSummary.nginx}`);

  // In automatic mode, we would:
  // 1. Write the config: await writeConfig(newConfig);
  // 2. Start the build: await startBuild();
  // 3. Poll for completion

  // For now, add to warnings that manual intervention is needed
  return {
    warnings: [
      `Attack Range needs reconfiguration. Missing: ${check.missing.join(', ')}`,
      'Run manually: python attack_range.py destroy && python attack_range.py build',
    ],
    current_step: 'attack_range_needs_rebuild',
  };
}

/**
 * Export utilities for use by other nodes
 */
export {
  getRangeStatus,
  analyzeRequiredInfra,
  checkRangeMeetsRequirements,
  generateConfig,
  writeConfig,
  startBuild,
};
