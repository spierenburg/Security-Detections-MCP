import { describe, it, expect } from 'vitest';
import { isValidTechniqueId, resolveUnder } from '../../tools/technique-id.js';

describe('isValidTechniqueId', () => {
  it.each(['T1003', 'T1003.001', 'T1059.001'])('accepts %s', (id) => {
    expect(isValidTechniqueId(id)).toBe(true);
  });

  it.each([
    '../../../../etc/cron.d/x',
    'T1003/../../x',
    'T1003.001/',
    't1003',
    'T100',
    'T1003.01',
    'T1003.001\n../x',
    '',
  ])('rejects %j', (id) => {
    expect(isValidTechniqueId(id)).toBe(false);
  });

  it('rejects non-strings', () => {
    expect(isValidTechniqueId(undefined)).toBe(false);
    expect(isValidTechniqueId(1003)).toBe(false);
  });
});

describe('resolveUnder', () => {
  it('resolves a child path', () => {
    expect(resolveUnder('/base', 'a', 'b')).toBe('/base/a/b');
  });

  it('throws on traversal out of base', () => {
    expect(() => resolveUnder('/base', 'a', '../../etc')).toThrow(/escapes/);
  });

  it('throws on a sibling that shares the base prefix', () => {
    expect(() => resolveUnder('/base', '../base-evil')).toThrow(/escapes/);
  });
});
