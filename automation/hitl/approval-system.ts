/**
 * Human-in-the-Loop (HITL) Approval System
 * 
 * Enables human checkpoints in autonomous workflows.
 * Pauses workflows and waits for explicit approval before proceeding.
 */

import { Database } from 'better-sqlite3';

interface ApprovalRequest {
  id: string;
  workflow_id: string;
  checkpoint_type: 'pr_creation' | 'high_impact_detection' | 'new_data_source' | 'high_fp_risk';
  status: 'pending' | 'approved' | 'rejected' | 'expired';
  data: string; // JSON: data being reviewed
  requested_at: string;
  resolved_at?: string;
  resolved_by?: string;
  timeout_hours: number;
  fallback_action: 'proceed' | 'cancel' | 'queue';
}

export class ApprovalSystem {
  private db: Database;

  constructor(databasePath: string) {
    // this.db = new Database(databasePath);
  }

  /**
   * Request approval for a workflow checkpoint
   */
  async requestApproval(
    workflowId: string,
    checkpointType: ApprovalRequest['checkpoint_type'],
    data: any,
    timeoutHours: number = 24
  ): Promise<string> {
    const approvalId = `approval_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    
    this.db.prepare(`
      INSERT INTO approval_requests (
        id, workflow_id, checkpoint_type, status, data, 
        requested_at, timeout_hours, fallback_action
      ) VALUES (?, ?, ?, 'pending', ?, CURRENT_TIMESTAMP, ?, 'cancel')
    `).run(
      approvalId,
      workflowId,
      checkpointType,
      JSON.stringify(data),
      timeoutHours
    );

    // Pause the workflow
    this.db.prepare(`
      UPDATE jobs 
      SET status = 'awaiting_approval' 
      WHERE workflow_id = ?
    `).run(workflowId);

    console.log(`[HITL] Approval requested: ${approvalId}`);
    console.log(`[HITL] Type: ${checkpointType}`);
    console.log(`[HITL] Workflow: ${workflowId}`);
    console.log(`[HITL] Timeout: ${timeoutHours} hours`);

    // Send notification
    await this.notifyApprovalNeeded(approvalId, checkpointType, data);

    return approvalId;
  }

  /**
   * Approve a pending request
   */
  async approve(approvalId: string, approver: string): Promise<void> {
    this.db.prepare(`
      UPDATE approval_requests 
      SET status = 'approved', resolved_at = CURRENT_TIMESTAMP, resolved_by = ?
      WHERE id = ? AND status = 'pending'
    `).run(approver, approvalId);

    // Resume the workflow
    const approval = this.getApproval(approvalId);
    if (approval) {
      this.db.prepare(`
        UPDATE jobs 
        SET status = 'pending' 
        WHERE workflow_id = ? AND status = 'awaiting_approval'
      `).run(approval.workflow_id);

      console.log(`[HITL] Approved: ${approvalId} by ${approver}`);
    }
  }

  /**
   * Reject a pending request
   */
  async reject(approvalId: string, rejector: string, reason?: string): Promise<void> {
    this.db.prepare(`
      UPDATE approval_requests 
      SET status = 'rejected', resolved_at = CURRENT_TIMESTAMP, resolved_by = ?
      WHERE id = ? AND status = 'pending'
    `).run(rejector, approvalId);

    // Cancel the workflow
    const approval = this.getApproval(approvalId);
    if (approval) {
      this.db.prepare(`
        UPDATE jobs 
        SET status = 'cancelled', error = ? 
        WHERE workflow_id = ? AND status = 'awaiting_approval'
      `).run(reason || 'Human rejected at approval checkpoint', approval.workflow_id);

      console.log(`[HITL] Rejected: ${approvalId} by ${rejector}`);
    }
  }

  /**
   * Get approval request details
   */
  getApproval(approvalId: string): ApprovalRequest | null {
    return this.db.prepare(`
      SELECT * FROM approval_requests WHERE id = ?
    `).get(approvalId) as ApprovalRequest | null;
  }

  /**
   * List pending approvals
   */
  getPendingApprovals(): ApprovalRequest[] {
    return this.db.prepare(`
      SELECT * FROM approval_requests 
      WHERE status = 'pending' 
      ORDER BY requested_at ASC
    `).all() as ApprovalRequest[];
  }

  /**
   * Check for expired approvals and handle fallback
   */
  async processExpiredApprovals(): Promise<void> {
    const expired = this.db.prepare(`
      SELECT * FROM approval_requests 
      WHERE status = 'pending' 
      AND datetime(requested_at, '+' || timeout_hours || ' hours') < datetime('now')
    `).all() as ApprovalRequest[];

    for (const approval of expired) {
      console.log(`[HITL] Approval expired: ${approval.id}`);
      
      this.db.prepare(`
        UPDATE approval_requests 
        SET status = 'expired', resolved_at = CURRENT_TIMESTAMP
        WHERE id = ?
      `).run(approval.id);

      // Apply fallback action
      switch (approval.fallback_action) {
        case 'proceed':
          console.log(`[HITL] Fallback: Proceeding with workflow ${approval.workflow_id}`);
          this.db.prepare(`UPDATE jobs SET status = 'pending' WHERE workflow_id = ?`)
            .run(approval.workflow_id);
          break;
        
        case 'cancel':
          console.log(`[HITL] Fallback: Cancelling workflow ${approval.workflow_id}`);
          this.db.prepare(`UPDATE jobs SET status = 'cancelled' WHERE workflow_id = ?`)
            .run(approval.workflow_id);
          break;
        
        case 'queue':
          console.log(`[HITL] Fallback: Re-queueing workflow ${approval.workflow_id}`);
          // Keep in awaiting_approval state for later review
          break;
      }
    }
  }

  /**
   * Send notification that approval is needed
   */
  private async notifyApprovalNeeded(
    approvalId: string,
    checkpointType: string,
    data: any
  ): Promise<void> {
    // Integrate with Slack/Discord/Email
    console.log(`[HITL] Notification needed for approval ${approvalId}`);
    
    // Example Slack message
    const message = {
      text: `⚠️ Human Approval Required: ${checkpointType}`,
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: `⚠️ Approval Required: ${checkpointType}`
          }
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `Approval ID: \`${approvalId}\`\n\nTo approve: \`approve ${approvalId}\`\nTo reject: \`reject ${approvalId} "reason"\``
          }
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `\`\`\`${JSON.stringify(data, null, 2)}\`\`\``
          }
        }
      ]
    };

    // Send via configured notification channels
    // await notifier.send(message);
  }

  /**
   * Initialize approval table if not exists
   */
  initializeSchema(): void {
    this.db.exec(`
      CREATE TABLE IF NOT EXISTS approval_requests (
        id TEXT PRIMARY KEY,
        workflow_id TEXT NOT NULL,
        checkpoint_type TEXT NOT NULL,
        status TEXT DEFAULT 'pending',
        data TEXT NOT NULL,
        requested_at TEXT DEFAULT CURRENT_TIMESTAMP,
        resolved_at TEXT,
        resolved_by TEXT,
        timeout_hours INTEGER DEFAULT 24,
        fallback_action TEXT DEFAULT 'cancel',
        
        FOREIGN KEY (workflow_id) REFERENCES jobs(workflow_id)
      );

      CREATE INDEX IF NOT EXISTS idx_approval_status 
        ON approval_requests(status, requested_at);
    `);
  }
}

// CLI entry point for approval management
if (require.main === module) {
  const dbPath = process.env.DETECTIONS_DB_PATH || './detections.db';
  const system = new ApprovalSystem(dbPath);

  const command = process.argv[2];
  const approvalId = process.argv[3];
  const approver = process.env.USER || 'unknown';

  switch (command) {
    case 'list':
      const pending = system.getPendingApprovals();
      console.log(`\nPending Approvals (${pending.length}):\n`);
      pending.forEach(a => {
        console.log(`ID: ${a.id}`);
        console.log(`Type: ${a.checkpoint_type}`);
        console.log(`Workflow: ${a.workflow_id}`);
        console.log(`Requested: ${a.requested_at}`);
        console.log('---');
      });
      break;

    case 'approve':
      if (!approvalId) {
        console.error('Usage: node approval-system.ts approve <approval_id>');
        process.exit(1);
      }
      system.approve(approvalId, approver).then(() => {
        console.log(`✅ Approved: ${approvalId}`);
      });
      break;

    case 'reject':
      if (!approvalId) {
        console.error('Usage: node approval-system.ts reject <approval_id> [reason]');
        process.exit(1);
      }
      const reason = process.argv[4] || 'No reason provided';
      system.reject(approvalId, approver, reason).then(() => {
        console.log(`❌ Rejected: ${approvalId}`);
      });
      break;

    case 'check-expired':
      system.processExpiredApprovals().then(() => {
        console.log('✅ Processed expired approvals');
      });
      break;

    default:
      console.log(`
Usage:
  node approval-system.ts list                    - List pending approvals
  node approval-system.ts approve <id>            - Approve a request
  node approval-system.ts reject <id> [reason]    - Reject a request
  node approval-system.ts check-expired           - Process expired requests
      `);
  }
}
