import { describe, it, expect, beforeEach } from 'vitest';
import { MCPClient, getMCPClient } from '../../tools/mcp-client.js';
import { setConfig, loadConfig, resetConfig } from '../../config.js';

describe('MCPClient', () => {
  let client: MCPClient;

  beforeEach(() => {
    resetConfig();
    const cfg = loadConfig();
    cfg.dryRun = true;
    setConfig(cfg);
    client = new MCPClient();
  });

  it('routes security-detections calls', async () => {
    const result = await client.callTool({
      server: 'security-detections',
      tool: 'search',
      arguments: { query: 'powershell', limit: 5 },
    });
    expect(result.success).toBe(true);
  });

  it('routes splunk-mcp calls (returns pending when MCP not enabled)', async () => {
    const result = await client.callTool({
      server: 'splunk-mcp',
      tool: 'search',
      arguments: { search: 'index=win' },
    });
    expect(result.success).toBe(true);
    const inner = result.result as any;
    // SPLUNK_MCP_ENABLED is not set, so client returns pending structure
    expect(inner._mcp_pending).toBe(true);
  });

  it('routes mitre-attack calls', async () => {
    const result = await client.callTool({
      server: 'mitre-attack',
      tool: 'get_technique',
      arguments: { id: 'T1059.001' },
    });
    expect(result.success).toBe(true);
    const inner = result.result as any;
    expect(inner._mcp_pending).toBe(true);
  });

  it('returns error for unknown server', async () => {
    const result = await client.callTool({
      server: 'unknown-server',
      tool: 'foo',
      arguments: {},
    });
    expect(result.success).toBe(false);
    expect(result.error).toContain('Unknown MCP server');
  });

  it('getMCPClient returns singleton', () => {
    const a = getMCPClient();
    const b = getMCPClient();
    expect(a).toBe(b);
  });
});
