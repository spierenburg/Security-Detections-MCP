/**
 * Autonomous Detection Engineering Loop
 * 
 * Watches the job queue and invokes Cursor subagents to process jobs autonomously.
 * This is the core orchestration runner for the autonomous detection platform.
 */

import { Database } from 'better-sqlite3';
import { exec } from 'child_process';
import { promisify } from 'util';

const execAsync = promisify(exec);

interface Job {
  id: string;
  job_type: string;
  status: string;
  priority: number;
  payload: string;
  retry_count: number;
  max_retries: number;
  workflow_id?: string;
}

interface FeedItem {
  id: string;
  feed_source: string;
  title: string;
  content: string;
  url: string;
  published_at: string;
}

export class AutonomousLoop {
  private db: Database;
  private isRunning: boolean = false;
  private pollInterval: number = 30000; // 30 seconds

  constructor(databasePath: string) {
    // In real implementation, would initialize better-sqlite3
    // this.db = new Database(databasePath);
  }

  /**
   * Get next pending job from queue (highest priority first)
   */
  getNextJob(): Job | null {
    const stmt = this.db.prepare(`
      SELECT * FROM jobs 
      WHERE status = 'pending' 
      AND retry_count < max_retries
      ORDER BY priority ASC, created_at ASC
      LIMIT 1
    `);

    return stmt.get() as Job | null;
  }

  /**
   * Mark job as running
   */
  markJobRunning(jobId: string): void {
    this.db.prepare(`
      UPDATE jobs 
      SET status = 'running', started_at = CURRENT_TIMESTAMP 
      WHERE id = ?
    `).run(jobId);
  }

  /**
   * Mark job as completed
   */
  markJobCompleted(jobId: string, result: any): void {
    this.db.prepare(`
      UPDATE jobs 
      SET status = 'completed', completed_at = CURRENT_TIMESTAMP, result = ?
      WHERE id = ?
    `).run(JSON.stringify(result), jobId);
  }

  /**
   * Mark job as failed and increment retry counter
   */
  markJobFailed(jobId: string, error: string): void {
    this.db.prepare(`
      UPDATE jobs 
      SET status = 'pending', retry_count = retry_count + 1, error = ?
      WHERE id = ?
    `).run(error, jobId);
  }

  /**
   * Get feed item details for a job
   */
  getFeedItem(feedItemId: string): FeedItem | null {
    const stmt = this.db.prepare(`
      SELECT * FROM feed_items WHERE id = ?
    `);

    return stmt.get(feedItemId) as FeedItem | null;
  }

  /**
   * Invoke Cursor subagent via shell
   * 
   * Note: This is a placeholder. Actual invocation would be:
   * 1. Via Cursor API if available
   * 2. Via MCP protocol directly
   * 3. Via Anthropic API with tool definitions
   */
  async invokeOrchestrator(job: Job): Promise<any> {
    const payload = JSON.parse(job.payload);
    
    if (job.job_type === 'threat_analysis') {
      const feedItem = this.getFeedItem(payload.feed_item_id);
      
      if (!feedItem) {
        throw new Error(`Feed item ${payload.feed_item_id} not found`);
      }

      console.log(`[Autonomous Loop] Processing: ${feedItem.title}`);
      console.log(`[Autonomous Loop] Source: ${feedItem.feed_source}`);
      console.log(`[Autonomous Loop] URL: ${feedItem.url}`);

      // In real implementation, would invoke orchestrator subagent:
      // const result = await invokeCursorSubagent('orchestrator', {
      //   prompt: `Process this threat intelligence:\n\nTitle: ${feedItem.title}\nURL: ${feedItem.url}\n\nContent:\n${feedItem.content}`,
      //   mode: 'autonomous'
      // });

      // For now, return a placeholder result structure
      return {
        job_id: job.id,
        feed_item_id: feedItem.id,
        techniques_extracted: [],
        gaps_identified: [],
        detections_created: [],
        validation_results: [],
        prs_staged: [],
        status: 'completed',
        timestamp: new Date().toISOString()
      };
    }

    throw new Error(`Unknown job type: ${job.job_type}`);
  }

  /**
   * Process a single job
   */
  async processJob(job: Job): Promise<void> {
    console.log(`[Autonomous Loop] Starting job ${job.id} (${job.job_type})`);
    
    try {
      this.markJobRunning(job.id);
      
      const result = await this.invokeOrchestrator(job);
      
      this.markJobCompleted(job.id, result);
      console.log(`[Autonomous Loop] Job ${job.id} completed successfully`);
      
    } catch (error: any) {
      console.error(`[Autonomous Loop] Job ${job.id} failed:`, error.message);
      this.markJobFailed(job.id, error.message);
    }
  }

  /**
   * Main loop - continuously watches queue and processes jobs
   */
  async start(): Promise<void> {
    console.log('[Autonomous Loop] Starting autonomous detection engineering loop...');
    console.log('[Autonomous Loop] Poll interval:', this.pollInterval / 1000, 'seconds');
    
    this.isRunning = true;

    while (this.isRunning) {
      try {
        const job = this.getNextJob();
        
        if (job) {
          await this.processJob(job);
        } else {
          // No jobs available, wait before checking again
          await this.sleep(this.pollInterval);
        }
        
      } catch (error) {
        console.error('[Autonomous Loop] Unexpected error:', error);
        await this.sleep(this.pollInterval);
      }
    }

    console.log('[Autonomous Loop] Stopped.');
  }

  /**
   * Stop the loop gracefully
   */
  stop(): void {
    console.log('[Autonomous Loop] Stopping...');
    this.isRunning = false;
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Get queue statistics
   */
  getStats(): any {
    const stats = this.db.prepare(`
      SELECT 
        status,
        COUNT(*) as count,
        job_type
      FROM jobs
      GROUP BY status, job_type
    `).all();

    return stats;
  }
}

// CLI entry point
if (require.main === module) {
  const dbPath = process.env.DETECTIONS_DB_PATH || './detections.db';
  const loop = new AutonomousLoop(dbPath);

  // Handle graceful shutdown
  process.on('SIGINT', () => {
    console.log('\n[Autonomous Loop] Received SIGINT, shutting down gracefully...');
    loop.stop();
    process.exit(0);
  });

  process.on('SIGTERM', () => {
    console.log('\n[Autonomous Loop] Received SIGTERM, shutting down gracefully...');
    loop.stop();
    process.exit(0);
  });

  // Start the loop
  loop.start().catch(error => {
    console.error('[Autonomous Loop] Fatal error:', error);
    process.exit(1);
  });
}
