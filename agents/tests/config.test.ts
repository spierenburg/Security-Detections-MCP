import { describe, it, expect, beforeEach, afterEach } from 'vitest';
import { loadConfig, validateConfig, getConfig, setConfig, resetConfig } from '../config.js';

describe('config', () => {
  const originalEnv = { ...process.env };

  beforeEach(() => {
    resetConfig();
  });

  afterEach(() => {
    process.env = { ...originalEnv };
    resetConfig();
  });

  it('returns sensible defaults when no env vars set', () => {
    delete process.env.SECURITY_CONTENT_PATH;
    delete process.env.ATTACK_DATA_PATH;
    delete process.env.ANTHROPIC_API_KEY;

    const cfg = loadConfig();
    expect(cfg.attackRangeEngine).toBe('ART');
    expect(cfg.maxDetectionsPerRun).toBe(3);
    expect(cfg.ingestionWaitSeconds).toBe(120);
    expect(cfg.dryRun).toBe(false);
    expect(cfg.splunkMcpEnabled).toBe(false);
  });

  it('reads env vars when provided', () => {
    process.env.ATTACK_RANGE_ENGINE = 'PurpleSharp';
    process.env.MAX_DETECTIONS_PER_RUN = '10';
    process.env.DRY_RUN = 'true';
    process.env.SPLUNK_MCP_ENABLED = 'true';

    const cfg = loadConfig();
    expect(cfg.attackRangeEngine).toBe('PurpleSharp');
    expect(cfg.maxDetectionsPerRun).toBe(10);
    expect(cfg.dryRun).toBe(true);
    expect(cfg.splunkMcpEnabled).toBe(true);
  });

  it('validateConfig flags missing API key', () => {
    delete process.env.ANTHROPIC_API_KEY;
    const cfg = loadConfig();
    const issues = validateConfig(cfg);
    expect(issues.some(i => i.includes('ANTHROPIC_API_KEY'))).toBe(true);
  });

  it('getConfig returns singleton', () => {
    const a = getConfig();
    const b = getConfig();
    expect(a).toBe(b);
  });

  it('setConfig overrides singleton', () => {
    const custom = loadConfig();
    custom.dryRun = true;
    setConfig(custom);
    expect(getConfig().dryRun).toBe(true);
  });
});
