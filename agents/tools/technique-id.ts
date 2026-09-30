/**
 * MITRE ATT&CK technique ID validation and path confinement.
 *
 * Technique IDs originate in LLM output over untrusted threat intel and are
 * later used as path segments, so they must be validated before any fs use.
 */

import { resolve, sep } from 'path';

export const TECHNIQUE_ID_PATTERN = /^T\d{4}(\.\d{3})?$/;

export function isValidTechniqueId(id: unknown): id is string {
  return typeof id === 'string' && TECHNIQUE_ID_PATTERN.test(id);
}

/**
 * Resolve `parts` under `base` and throw if the result escapes `base`.
 * Defence in depth behind isValidTechniqueId.
 */
export function resolveUnder(base: string, ...parts: string[]): string {
  const root = resolve(base);
  const target = resolve(root, ...parts);
  if (target !== root && !target.startsWith(root + sep)) {
    throw new Error(`Path escapes base directory: ${target}`);
  }
  return target;
}
