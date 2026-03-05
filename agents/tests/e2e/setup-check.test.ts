import { describe, it, expect, beforeAll } from 'vitest';
import { loadConfig, validateConfig } from '../../config.js';

describe('E2E setup check', () => {
  const cfg = loadConfig();

  it('config loads without throwing', () => {
    expect(cfg).toBeDefined();
    expect(cfg.attackRangeEngine).toBeDefined();
  });

  it('reports missing env vars clearly', () => {
    const issues = validateConfig(cfg);
    // this test just prints the issues so a human can see what's missing
    if (issues.length > 0) {
      console.log('Setup issues found (fix these for a full run):');
      issues.forEach(i => console.log(`  - ${i}`));
    }
    // always pass – this is an informational check
    expect(true).toBe(true);
  });

  it('MCP client can be instantiated', async () => {
    const { getMCPClient } = await import('../../tools/mcp-client.js');
    const client = getMCPClient();
    expect(client).toBeDefined();
  });
});
