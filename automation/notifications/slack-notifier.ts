/**
 * Slack Webhook Notifier
 * 
 * Sends notifications to Slack for detection validation results, PRs, and coverage updates.
 */

import https from 'https';

interface SlackMessage {
  text?: string;
  blocks?: any[];
  attachments?: any[];
}

interface NotificationTemplate {
  detection_validated: (data: any) => SlackMessage;
  validation_failed: (data: any) => SlackMessage;
  coverage_gap: (data: any) => SlackMessage;
  prs_staged: (data: any) => SlackMessage;
}

export class SlackNotifier {
  private webhookUrl: string;
  private channel: string;

  constructor(webhookUrl: string, channel: string = '#detection-engineering') {
    this.webhookUrl = webhookUrl;
    this.channel = channel;
  }

  /**
   * Send message to Slack webhook
   */
  async send(message: SlackMessage): Promise<void> {
    const payload = JSON.stringify({
      ...message,
      channel: this.channel
    });

    return new Promise((resolve, reject) => {
      const url = new URL(this.webhookUrl);
      
      const req = https.request({
        hostname: url.hostname,
        path: url.pathname + url.search,
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          'Content-Length': Buffer.byteLength(payload)
        }
      }, (res) => {
        if (res.statusCode === 200) {
          resolve();
        } else {
          reject(new Error(`Slack webhook returned ${res.statusCode}`));
        }
      });

      req.on('error', reject);
      req.write(payload);
      req.end();
    });
  }

  /**
   * Notification templates
   */
  templates: NotificationTemplate = {
    detection_validated: (data) => ({
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: `✅ Detection VALIDATED: ${data.detection_name}`
          }
        },
        {
          type: 'section',
          fields: [
            {
              type: 'mrkdwn',
              text: `*Technique:*\n${data.mitre_id}`
            },
            {
              type: 'mrkdwn',
              text: `*Atomic Test:*\n${data.atomic_id}`
            },
            {
              type: 'mrkdwn',
              text: `*Event Count:*\n${data.result_count}`
            },
            {
              type: 'mrkdwn',
              text: `*Source:*\n${data.threat_source}`
            }
          ]
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*PRs Staged (REVIEW REQUIRED):*\n• Detection: <${data.detection_pr_url}|View PR>\n• Attack Data: <${data.attack_data_pr_url}|View PR>`
          }
        },
        {
          type: 'context',
          elements: [
            {
              type: 'mrkdwn',
              text: '_Staged by Autonomous Detection Agent. Human review required before merge._'
            }
          ]
        }
      ]
    }),

    validation_failed: (data) => ({
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: `❌ Detection FAILED Validation: ${data.detection_name}`
          }
        },
        {
          type: 'section',
          fields: [
            {
              type: 'mrkdwn',
              text: `*Technique:*\n${data.mitre_id}`
            },
            {
              type: 'mrkdwn',
              text: `*Failure Type:*\n${data.failure_reason}`
            }
          ]
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Debug Info:*\n\`\`\`${data.debug_log}\`\`\``
          }
        },
        {
          type: 'context',
          elements: [
            {
              type: 'mrkdwn',
              text: '_Agent will retry after refinement._'
            }
          ]
        }
      ]
    }),

    coverage_gap: (data) => ({
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: `🔍 Coverage Gap Identified: ${data.technique}`
          }
        },
        {
          type: 'section',
          fields: [
            {
              type: 'mrkdwn',
              text: `*Threat Actor:*\n${data.threat_actor}`
            },
            {
              type: 'mrkdwn',
              text: `*Missing Detections:*\n${data.gap_count}`
            },
            {
              type: 'mrkdwn',
              text: `*Priority:*\n${data.priority}`
            },
            {
              type: 'mrkdwn',
              text: `*Data Source:*\n${data.data_source_status}`
            }
          ]
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Recommended Action:*\n${data.recommended_action}`
          }
        }
      ]
    }),

    prs_staged: (data) => ({
      blocks: [
        {
          type: 'header',
          text: {
            type: 'plain_text',
            text: `📦 Dual PRs Staged: ${data.detection_count} detections`
          }
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*security_content PRs:*\n${data.content_prs.map((pr: string) => `• <${pr}|View PR>`).join('\n')}`
          }
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*attack_data PRs:*\n${data.data_prs.map((pr: string) => `• <${pr}|View PR>`).join('\n')}`
          }
        },
        {
          type: 'section',
          text: {
            type: 'mrkdwn',
            text: `*Coverage Improvement:*\n${data.coverage_improvement}% increase`
          }
        }
      ]
    })
  };

  /**
   * Convenience methods for common notifications
   */
  async notifyDetectionValidated(data: any): Promise<void> {
    await this.send(this.templates.detection_validated(data));
  }

  async notifyValidationFailed(data: any): Promise<void> {
    await this.send(this.templates.validation_failed(data));
  }

  async notifyCoverageGap(data: any): Promise<void> {
    await this.send(this.templates.coverage_gap(data));
  }

  async notifyPRsStaged(data: any): Promise<void> {
    await this.send(this.templates.prs_staged(data));
  }
}

// CLI entry point for testing
if (require.main === module) {
  const webhookUrl = process.env.SLACK_WEBHOOK_URL;
  
  if (!webhookUrl) {
    console.error('Error: SLACK_WEBHOOK_URL environment variable not set');
    process.exit(1);
  }

  const notifier = new SlackNotifier(webhookUrl);
  
  // Test notification
  notifier.notifyDetectionValidated({
    detection_name: 'Windows LSASS Memory Dump',
    mitre_id: 'T1003.001',
    atomic_id: 'T1003.001-1',
    result_count: 5,
    threat_source: 'CISA Alert AA24-131A',
    detection_pr_url: 'https://github.com/splunk/security_content/pull/1234',
    attack_data_pr_url: 'https://github.com/splunk/attack_data/pull/567'
  }).then(() => {
    console.log('Test notification sent successfully');
  }).catch(error => {
    console.error('Failed to send test notification:', error);
  });
}
