/**
 * PR Stager Node
 * 
 * Stages DRAFT PRs to security_content and attack_data repos.
 * CRITICAL: NEVER auto-merge - always create as DRAFT for human review.
 */

import { execFile } from 'child_process';
import { promisify } from 'util';
import { getConfig } from '../config.js';
import { isValidTechniqueId } from '../tools/technique-id.js';
import type { PipelineState, PR, Detection } from '../state/types.js';

const execFileAsync = promisify(execFile);

export async function prStagerNode(state: PipelineState): Promise<Partial<PipelineState>> {
  console.log('[PR Stager] Preparing to stage PRs...');
  
  const cfg = getConfig();
  
  // Dry-run mode: return mock PR info
  if (cfg.dryRun) {
    console.log('[PR Stager] Dry-run mode - returning mock PR info');
    const validatedCount = state.detections.filter(d => d.status === 'validated').length;
    
    const mockPRs: PR[] = [
      {
        repo: 'mock/security_content',
        branch: `autonomous-detection-${state.workflow_id.substring(0, 8)}`,
        url: 'https://github.com/mock/security_content/pull/999',
        status: 'draft' as const,
      }
    ];
    
    console.log(`[PR Stager] Mock staged ${mockPRs.length} DRAFT PR(s) for ${validatedCount} detection(s)`);
    
    return {
      prs: mockPRs,
      current_step: 'pr_staging_complete',
      warnings: ['Dry-run mode: no actual PRs created'],
    };
  }
  
  // Only stage validated detections
  // technique_id is LLM-derived: only well-formed IDs go into commit/PR text. `name` is not sanitized (markdown/@mention in the PR body).
  const validatedDetections = state.detections.filter(d => d.status === 'validated' && isValidTechniqueId(d.technique_id));
  
  if (validatedDetections.length === 0) {
    console.log('[PR Stager] No validated detections to stage');
    return { current_step: 'pr_staging_complete' };
  }

  // Check if human approval is required
  if (state.requires_approval && !state.approved) {
    console.log('[PR Stager] Awaiting human approval before staging PRs');
    return {
      requires_approval: true,
      approval_reason: `Stage ${validatedDetections.length} detection(s) as DRAFT PRs?`,
      current_step: 'awaiting_approval',
    };
  }

  const prs: PR[] = [];
  const branchName = `autonomous-detection-${state.workflow_id.substring(0, 8)}`;
  const timestamp = new Date().toISOString();

  try {
    // Stage security_content PR
    console.log('[PR Stager] Creating security_content branch and PR...');
    
    const detectionFiles = validatedDetections.map(d => d.file_path);
    const techniques = validatedDetections.map(d => d.technique_id).join(', ');
    
    // Create branch, add files, commit, push. argv only, no shell: file_path and IDs are never parsed by bash.
    const git = (...args: string[]) => execFileAsync('git', args, { cwd: cfg.securityContentPath });
    await git('checkout', 'develop');
    await git('pull', 'origin', 'develop');
    await git('checkout', '-b', branchName);
    await git('add', '--', ...detectionFiles);
    await git('commit', '-m', `Add automated detections for ${techniques}`);
    await git('push', '-u', 'origin', branchName);

    // Create DRAFT PR using gh CLI
    const prTitle = `[Autonomous] Add detections for ${techniques}`;
    const prBody = `## Summary
- **Techniques**: ${techniques}
- **Detections**: ${validatedDetections.length}
- **Validation**: All detections validated via Atomic Red Team
- **Generated**: ${timestamp}

## Detections Added
${validatedDetections.map(d => `- \`${d.name}\` (${d.technique_id})`).join('\n')}

## Test Plan
- [x] Detection created following security_content conventions
- [x] Atomic Red Team test executed
- [x] Detection validated in Splunk (events matched)
- [ ] Human review required

---
*This PR was created by the Autonomous Detection Platform. Human review is required before merging.*`;

    const { stdout: prUrl } = await execFileAsync(
      'gh',
      ['pr', 'create', '--draft', '--title', prTitle, '--body', prBody],
      { cwd: cfg.securityContentPath },
    );
    
    prs.push({
      repo: 'splunk/security_content',
      branch: branchName,
      url: prUrl.trim(),
      status: 'staged',
    });

    console.log(`[PR Stager] ✓ security_content DRAFT PR created: ${prUrl.trim()}`);

  } catch (error) {
    console.error('[PR Stager] Error staging security_content PR:', error);
    prs.push({
      repo: 'splunk/security_content',
      branch: branchName,
      status: 'failed',
    });
  }

  // Attack data PR would go here (similar pattern)
  // For now, we'll note it as pending
  if (state.attack_data_paths.length > 0) {
    console.log('[PR Stager] Attack data PR staging not yet implemented');
    prs.push({
      repo: 'splunk/attack_data',
      branch: branchName,
      status: 'pending',
    });
  }

  const stagedCount = prs.filter(p => p.status === 'staged').length;
  console.log(`[PR Stager] Staged ${stagedCount} DRAFT PR(s)`);

  return {
    prs,
    current_step: 'pr_staging_complete',
  };
}
