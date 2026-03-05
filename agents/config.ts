/**
 * Pipeline Configuration
 *
 * All paths and settings are loaded from environment variables with sensible
 * defaults so the pipeline is portable across machines.
 */

import { existsSync } from 'fs';
import { resolve } from 'path';

export interface PipelineConfig {
  // repo paths
  securityContentPath: string;
  attackDataPath: string;
  attackRangePath: string;

  // Attack Range
  attackRangeVenv: string;
  attackRangeDefaultTarget: string;
  attackRangeEngine: string;
  attackRangeCustomPlaybook: string;

  // LLM
  anthropicApiKey: string | undefined;
  llmModel: string;

  // MCP
  splunkMcpEnabled: boolean;
  mcpServerUrl: string;

  // Pipeline behaviour
  dryRun: boolean;
  siemPlatform: 'splunk' | 'sentinel' | 'elastic' | 'sigma';
  maxDetectionsPerRun: number;
  ingestionWaitSeconds: number;
}

function envOrDefault(key: string, fallback: string): string {
  return process.env[key] || fallback;
}

export function loadConfig(): PipelineConfig {
  return {
    securityContentPath: resolve(envOrDefault('SECURITY_CONTENT_PATH', './security_content')),
    attackDataPath: resolve(envOrDefault('ATTACK_DATA_PATH', './attack_data')),
    attackRangePath: resolve(envOrDefault('ATTACK_RANGE_PATH', './attack_range')),

    attackRangeVenv: envOrDefault('ATTACK_RANGE_VENV', ''),
    attackRangeDefaultTarget: envOrDefault('ATTACK_RANGE_DEFAULT_TARGET', ''),
    attackRangeEngine: envOrDefault('ATTACK_RANGE_ENGINE', 'ART'),
    attackRangeCustomPlaybook: envOrDefault('ATTACK_RANGE_CUSTOM_PLAYBOOK', 'deploy_custom_atomics.yml'),

    anthropicApiKey: process.env.ANTHROPIC_API_KEY,
    llmModel: envOrDefault('LLM_MODEL', 'claude-sonnet-4-20250514'),

    splunkMcpEnabled: process.env.SPLUNK_MCP_ENABLED === 'true',
    mcpServerUrl: envOrDefault('MCP_SERVER_URL', 'stdio'),

    dryRun: process.env.DRY_RUN === 'true',
    siemPlatform: (envOrDefault('SIEM_PLATFORM', 'splunk') as 'splunk' | 'sentinel' | 'elastic' | 'sigma'),
    maxDetectionsPerRun: parseInt(envOrDefault('MAX_DETECTIONS_PER_RUN', '3'), 10),
    ingestionWaitSeconds: parseInt(envOrDefault('INGESTION_WAIT_SECONDS', '120'), 10),
  };
}

/**
 * Validate that required config is present. Returns a list of problems
 * (empty = all good).
 */
export function validateConfig(cfg: PipelineConfig): string[] {
  const issues: string[] = [];

  if (!cfg.anthropicApiKey) {
    issues.push('ANTHROPIC_API_KEY is not set');
  }

  if (!existsSync(cfg.securityContentPath)) {
    issues.push(`SECURITY_CONTENT_PATH does not exist: ${cfg.securityContentPath}`);
  }

  return issues;
}

// singleton so nodes don't have to call loadConfig() every time
let _config: PipelineConfig | null = null;

export function getConfig(): PipelineConfig {
  if (!_config) {
    _config = loadConfig();
  }
  return _config;
}

// allow tests to inject a config
export function setConfig(cfg: PipelineConfig): void {
  _config = cfg;
}

export function resetConfig(): void {
  _config = null;
}
