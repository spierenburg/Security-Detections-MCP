/**
 * Cron-Based Job Scheduler
 * 
 * Manages scheduled jobs from job_schedule table using cron expressions.
 */

import { Database } from 'better-sqlite3';
import { CronJob } from 'cron';

interface ScheduledJob {
  id: string;
  name: string;
  cron_expression: string;
  job_type: string;
  payload: string;
  enabled: number;
  last_run: string | null;
  next_run: string | null;
}

export class CronScheduler {
  private db: Database;
  private jobs: Map<string, CronJob> = new Map();

  constructor(databasePath: string) {
    // this.db = new Database(databasePath);
  }

  /**
   * Load all enabled scheduled jobs from database
   */
  loadSchedules(): ScheduledJob[] {
    return this.db.prepare(`
      SELECT * FROM job_schedule 
      WHERE enabled = 1
      ORDER BY name
    `).all() as ScheduledJob[];
  }

  /**
   * Create a job in the queue
   */
  createJob(jobType: string, payload: any): string {
    const jobId = `job_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    
    this.db.prepare(`
      INSERT INTO jobs (id, job_type, status, payload, created_at)
      VALUES (?, ?, 'pending', ?, CURRENT_TIMESTAMP)
    `).run(jobId, jobType, JSON.stringify(payload));

    console.log(`[Cron Scheduler] Created job ${jobId} (${jobType})`);
    return jobId;
  }

  /**
   * Update schedule last_run and next_run times
   */
  updateScheduleRunTimes(scheduleId: string, nextRun: Date): void {
    this.db.prepare(`
      UPDATE job_schedule 
      SET last_run = CURRENT_TIMESTAMP, next_run = ?
      WHERE id = ?
    `).run(nextRun.toISOString(), scheduleId);
  }

  /**
   * Start the scheduler
   */
  start(): void {
    console.log('[Cron Scheduler] Loading scheduled jobs...');
    
    const schedules = this.loadSchedules();
    
    for (const schedule of schedules) {
      try {
        const cronJob = new CronJob(
          schedule.cron_expression,
          () => this.executeScheduledJob(schedule),
          null,
          true,  // Start immediately
          'America/New_York'  // Timezone
        );

        this.jobs.set(schedule.id, cronJob);
        
        const nextRun = cronJob.nextDate().toJSDate();
        this.updateScheduleRunTimes(schedule.id, nextRun);

        console.log(`[Cron Scheduler] Scheduled: ${schedule.name}`);
        console.log(`[Cron Scheduler]   Cron: ${schedule.cron_expression}`);
        console.log(`[Cron Scheduler]   Next: ${nextRun.toISOString()}`);
        
      } catch (error) {
        console.error(`[Cron Scheduler] Failed to schedule ${schedule.name}:`, error);
      }
    }

    console.log(`[Cron Scheduler] Started ${this.jobs.size} scheduled jobs`);
  }

  /**
   * Execute a scheduled job
   */
  private executeScheduledJob(schedule: ScheduledJob): void {
    console.log(`[Cron Scheduler] Executing: ${schedule.name} (${schedule.job_type})`);
    
    try {
      const payload = schedule.payload ? JSON.parse(schedule.payload) : {};
      const jobId = this.createJob(schedule.job_type, payload);
      
      // Update next run time
      const cronJob = this.jobs.get(schedule.id);
      if (cronJob) {
        const nextRun = cronJob.nextDate().toJSDate();
        this.updateScheduleRunTimes(schedule.id, nextRun);
      }
      
      console.log(`[Cron Scheduler] Scheduled job ${schedule.name} -> Job ${jobId}`);
    } catch (error) {
      console.error(`[Cron Scheduler] Failed to execute ${schedule.name}:`, error);
    }
  }

  /**
   * Stop all scheduled jobs
   */
  stop(): void {
    console.log('[Cron Scheduler] Stopping all scheduled jobs...');
    
    for (const [id, job] of this.jobs.entries()) {
      job.stop();
    }
    
    this.jobs.clear();
    console.log('[Cron Scheduler] Stopped');
  }

  /**
   * Get status of all scheduled jobs
   */
  getStatus(): any {
    const schedules = this.loadSchedules();
    
    return schedules.map(s => ({
      id: s.id,
      name: s.name,
      cron: s.cron_expression,
      job_type: s.job_type,
      enabled: s.enabled === 1,
      last_run: s.last_run,
      next_run: s.next_run,
      is_running: this.jobs.has(s.id)
    }));
  }

  /**
   * Add a new scheduled job
   */
  addSchedule(
    name: string,
    cronExpression: string,
    jobType: string,
    payload: any = null
  ): string {
    const scheduleId = `sched_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    
    this.db.prepare(`
      INSERT INTO job_schedule (
        id, name, cron_expression, job_type, payload, enabled
      ) VALUES (?, ?, ?, ?, ?, 1)
    `).run(
      scheduleId,
      name,
      cronExpression,
      jobType,
      payload ? JSON.stringify(payload) : null
    );

    console.log(`[Cron Scheduler] Added schedule: ${name}`);
    return scheduleId;
  }

  /**
   * Remove a scheduled job
   */
  removeSchedule(scheduleId: string): void {
    const job = this.jobs.get(scheduleId);
    if (job) {
      job.stop();
      this.jobs.delete(scheduleId);
    }

    this.db.prepare(`DELETE FROM job_schedule WHERE id = ?`).run(scheduleId);
    
    console.log(`[Cron Scheduler] Removed schedule: ${scheduleId}`);
  }
}

// CLI entry point
if (require.main === module) {
  const dbPath = process.env.DETECTIONS_DB_PATH || './detections.db';
  const scheduler = new CronScheduler(dbPath);

  const command = process.argv[2];

  switch (command) {
    case 'start':
      scheduler.start();
      console.log('[Cron Scheduler] Running... Press Ctrl+C to stop');
      
      // Keep process alive
      process.on('SIGINT', () => {
        console.log('\n[Cron Scheduler] Shutting down...');
        scheduler.stop();
        process.exit(0);
      });
      break;

    case 'status':
      const status = scheduler.getStatus();
      console.log('\nScheduled Jobs:\n');
      console.table(status);
      process.exit(0);
      break;

    case 'add':
      const [, , , name, cron, jobType, payload] = process.argv;
      if (!name || !cron || !jobType) {
        console.error('Usage: node cron-scheduler.ts add <name> <cron> <job_type> [payload_json]');
        process.exit(1);
      }
      const payloadObj = payload ? JSON.parse(payload) : null;
      scheduler.addSchedule(name, cron, jobType, payloadObj);
      process.exit(0);
      break;

    default:
      console.log(`
Usage:
  node cron-scheduler.ts start                    - Start the scheduler
  node cron-scheduler.ts status                   - View schedule status
  node cron-scheduler.ts add <name> <cron> <type> - Add new schedule

Examples:
  # Start scheduler
  node cron-scheduler.ts start

  # Add hourly feed collection
  node cron-scheduler.ts add "Hourly CISA" "0 * * * *" feed_collection

  # Add weekly coverage report
  node cron-scheduler.ts add "Weekly Report" "0 0 * * 1" coverage_report '{"type":"weekly"}'
      `);
  }
}
