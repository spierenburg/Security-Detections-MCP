/**
 * CISA RSS Feed Collector
 * 
 * Collects threat intelligence from CISA's RSS feeds and inserts into the job queue.
 * Designed to run as a background process or cron job.
 */

import { Database } from 'better-sqlite3';
import { createHash } from 'crypto';

interface CISAFeedItem {
  id: string;
  title: string;
  link: string;
  description: string;
  pubDate: Date;
  guid: string;
}

interface FeedConfig {
  url: string;
  feedSource: string;
  pollInterval: number; // seconds
  enabled: boolean;
}

const FEEDS: FeedConfig[] = [
  {
    url: 'https://www.cisa.gov/uscert/ncas/alerts.xml',
    feedSource: 'cisa_alerts',
    pollInterval: 3600, // 1 hour
    enabled: true
  },
  {
    url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
    feedSource: 'cisa_kev',
    pollInterval: 86400, // 24 hours
    enabled: true
  }
];

export class CISARSSCollector {
  private db: Database;
  private feedparser: any; // Will be dynamically imported

  constructor(databasePath: string) {
    // In real implementation, would initialize better-sqlite3
    // this.db = new Database(databasePath);
  }

  /**
   * Initialize feedparser library
   * Note: feedparser is Python-based, so we'll shell out or use node-feedparser
   */
  private async initFeedParser(): Promise<void> {
    // Dynamic import to avoid bundling if not needed
    try {
      this.feedparser = await import('feedparser-promised');
    } catch (error) {
      console.error('feedparser not installed. Run: npm install feedparser-promised');
      throw error;
    }
  }

  /**
   * Fetch and parse RSS feed
   */
  async fetchFeed(feedUrl: string): Promise<CISAFeedItem[]> {
    await this.initFeedParser();
    
    try {
      const items = await this.feedparser.parse(feedUrl);
      
      return items.map((item: any) => ({
        id: this.generateFeedItemId(item.guid || item.link),
        title: item.title,
        link: item.link,
        description: item.description || item.summary,
        pubDate: new Date(item.pubdate || item.date),
        guid: item.guid || item.link
      }));
    } catch (error) {
      console.error(`Failed to fetch feed ${feedUrl}:`, error);
      return [];
    }
  }

  /**
   * Generate deterministic ID from feed item GUID
   */
  private generateFeedItemId(guid: string): string {
    return createHash('sha256').update(guid).digest('hex').substring(0, 16);
  }

  /**
   * Insert feed item into database if not already exists
   */
  async insertFeedItem(item: CISAFeedItem, feedSource: string): Promise<boolean> {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO feed_items (
        id, feed_source, title, content, url, published_at, status
      ) VALUES (?, ?, ?, ?, ?, ?, 'pending')
    `);

    const result = stmt.run(
      item.id,
      feedSource,
      item.title,
      item.description,
      item.link,
      item.pubDate.toISOString()
    );

    return result.changes > 0; // True if new item inserted
  }

  /**
   * Create job for feed item processing
   */
  async createJobForFeedItem(feedItemId: string): Promise<string> {
    const jobId = `job_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    
    const stmt = this.db.prepare(`
      INSERT INTO jobs (id, job_type, status, priority, payload, created_at)
      VALUES (?, 'threat_analysis', 'pending', 5, ?, CURRENT_TIMESTAMP)
    `);

    stmt.run(jobId, JSON.stringify({ feed_item_id: feedItemId }));

    // Link job to feed item
    this.db.prepare(`UPDATE feed_items SET job_id = ? WHERE id = ?`)
      .run(jobId, feedItemId);

    return jobId;
  }

  /**
   * Main collection loop - fetches feeds and creates jobs
   */
  async collectFeeds(): Promise<void> {
    console.log('[CISA Collector] Starting feed collection...');

    for (const feed of FEEDS.filter(f => f.enabled)) {
      try {
        console.log(`[CISA Collector] Fetching ${feed.feedSource}...`);
        const items = await this.fetchFeed(feed.url);
        
        let newItems = 0;
        for (const item of items) {
          const isNew = await this.insertFeedItem(item, feed.feedSource);
          
          if (isNew) {
            newItems++;
            const jobId = await this.createJobForFeedItem(item.id);
            console.log(`[CISA Collector] New item: ${item.title} -> Job ${jobId}`);
          }
        }

        console.log(`[CISA Collector] ${feed.feedSource}: ${newItems} new items (${items.length} total)`);
      } catch (error) {
        console.error(`[CISA Collector] Error processing ${feed.feedSource}:`, error);
      }
    }

    console.log('[CISA Collector] Collection complete.');
  }

  /**
   * Run continuous collection loop with interval
   */
  async runContinuous(intervalSeconds: number = 3600): Promise<void> {
    console.log(`[CISA Collector] Starting continuous mode (interval: ${intervalSeconds}s)`);

    while (true) {
      await this.collectFeeds();
      await this.sleep(intervalSeconds * 1000);
    }
  }

  private sleep(ms: number): Promise<void> {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

// CLI entry point
if (require.main === module) {
  const dbPath = process.env.DETECTIONS_DB_PATH || './detections.db';
  const collector = new CISARSSCollector(dbPath);
  
  const mode = process.argv[2] || 'once';
  
  if (mode === 'continuous') {
    collector.runContinuous(3600); // 1 hour
  } else {
    collector.collectFeeds().then(() => {
      console.log('[CISA Collector] Done.');
      process.exit(0);
    });
  }
}
