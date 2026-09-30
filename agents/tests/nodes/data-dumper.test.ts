import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { mkdtempSync, mkdirSync, existsSync, readdirSync, rmSync } from 'fs';
import { tmpdir } from 'os';
import { join } from 'path';
import { setConfig, loadConfig, resetConfig } from '../../config.js';

const callTool = vi.fn().mockResolvedValue({ success: false });

vi.mock('../../tools/mcp-client.js', () => ({
  getMCPClient: () => ({ callTool }),
  splunkExportDump: vi.fn(),
}));

import { dataDumperNode } from '../../nodes/data-dumper.js';

describe('dataDumperNode technique_id confinement', () => {
  let root: string;
  let base: string;

  beforeEach(() => {
    callTool.mockClear();
    root = mkdtempSync(join(tmpdir(), 'dumper-'));
    base = join(root, 'attack_data');
    mkdirSync(base);
    resetConfig();
    const cfg = loadConfig();
    cfg.attackDataPath = base;
    cfg.dryRun = false;
    setConfig(cfg);
  });

  afterEach(() => {
    rmSync(root, { recursive: true, force: true });
  });

  const detection = (technique_id: string): any => ({
    id: '1',
    name: 'd',
    technique_id,
    file_path: '/tmp/d.yml',
    status: 'validated',
  });

  it('refuses a traversal technique_id and writes nothing outside the base', async () => {
    const result = await dataDumperNode({
      detections: [detection('../../../evil')],
    } as any);

    expect(result.attack_data_paths).toEqual([]);
    expect(callTool).not.toHaveBeenCalled();
    expect(readdirSync(root)).toEqual(['attack_data']);
    expect(existsSync(join(base, 'datasets'))).toBe(false);
  });

  it('still exports for a well-formed technique_id', async () => {
    await dataDumperNode({ detections: [detection('T1003.001')] } as any);

    expect(callTool).toHaveBeenCalled();
    expect(existsSync(join(base, 'datasets', 'attack_techniques', 'T1003.001', 'autonomous_agent'))).toBe(true);
  });
});
