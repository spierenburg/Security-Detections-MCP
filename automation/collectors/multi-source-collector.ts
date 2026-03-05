/**
 * Multi-Source Threat Intelligence Collector
 * 
 * Collects from various threat intelligence sources beyond CISA.
 */

import { Database } from 'better-sqlite3';
import { createHash } from 'crypto';
import https from 'https';

interface FeedSource {
  id: string;
  name: string;
  type: 'rss' | 'json' | 'github' | 'api';
  url: string;
  pollInterval: number;
  enabled: boolean;
  parser: (data: any) => FeedItem[];
}

interface FeedItem {
  id: string;
  title: string;
  content: string;
  url: string;
  publishedAt: Date;
}

export class MultiSourceCollector {
  private db: Database;

  constructor(databasePath: string) {
    // In real implementation, would initialize better-sqlite3
    // this.db = new Database(databasePath);
  }

  /**
   * Feed source definitions
   */
  readonly sources: FeedSource[] = [
    // CISA Feeds
    {
      id: 'cisa_alerts',
      name: 'CISA Cybersecurity Advisories',
      type: 'rss',
      url: 'https://www.cisa.gov/uscert/ncas/alerts.xml',
      pollInterval: 3600,
      enabled: true,
      parser: this.parseRSS
    },
    {
      id: 'cisa_kev',
      name: 'CISA Known Exploited Vulnerabilities',
      type: 'json',
      url: 'https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json',
      pollInterval: 86400,
      enabled: true,
      parser: this.parseCISAKEV
    },

    // MITRE ATT&CK
    {
      id: 'mitre_attack',
      name: 'MITRE ATT&CK Updates',
      type: 'github',
      url: 'https://api.github.com/repos/mitre/cti/commits',
      pollInterval: 86400,
      enabled: true,
      parser: this.parseMITRECommits
    },

    // Vendor Blogs (examples)
    {
      id: 'microsoft_security',
      name: 'Microsoft Security Blog',
      type: 'rss',
      url: 'https://www.microsoft.com/security/blog/feed/',
      pollInterval: 86400,
      enabled: false, // Enable as needed
      parser: this.parseRSS
    },
    {
      id: 'crowdstrike_blog',
      name: 'CrowdStrike Threat Intel',
      type: 'rss',
      url: 'https://www.crowdstrike.com/blog/feed/',
      pollInterval: 86400,
      enabled: false,
      parser: this.parseRSS
    },
    {
      id: 'mandiant_threat_intel',
      name: 'Mandiant Threat Intelligence',
      type: 'rss',
      url: 'https://www.mandiant.com/resources/blog/rss.xml',
      pollInterval: 86400,
      enabled: false,
      parser: this.parseRSS
    },

    // CVE Feeds
    {
      id: 'nvd_recent',
      name: 'NVD Recent CVEs',
      type: 'json',
      url: 'https://services.nvd.nist.gov/rest/json/cves/2.0?resultsPerPage=100',
      pollInterval: 86400,
      enabled: false,
      parser: this.parseNVD
    },

    // SigmaHQ (new detection rules)
    {
      id: 'sigmahq_rules',
      name: 'SigmaHQ New Rules',
      type: 'github',
      url: 'https://api.github.com/repos/SigmaHQ/sigma/commits?path=rules',
      pollInterval: 86400,
      enabled: false,
      parser: this.parseSigmaCommits
    }
  ];

  /**
   * RSS Feed Parser
   */
  private async parseRSS(data: string): Promise<FeedItem[]> {
    // Use feedparser-promised or similar
    // Placeholder implementation
    return [];
  }

  /**
   * CISA KEV JSON Parser
   */
  private async parseCISAKEV(data: string): Promise<FeedItem[]> {
    try {
      const json = JSON.parse(data);
      const vulnerabilities = json.vulnerabilities || [];

      return vulnerabilities.slice(0, 10).map((vuln: any) => ({
        id: this.generateId(`cisa-kev-${vuln.cveID}`),
        title: `CVE ${vuln.cveID}: ${vuln.vulnerabilityName}`,
        content: `
Vendor: ${vuln.vendorProject}
Product: ${vuln.product}
Known Ransomware Use: ${vuln.knownRansomwareCampaignUse}
Date Added: ${vuln.dateAdded}
Required Action: ${vuln.requiredAction}
        `.trim(),
        url: `https://www.cve.org/CVERecord?id=${vuln.cveID}`,
        publishedAt: new Date(vuln.dateAdded)
      }));
    } catch (error) {
      console.error('Failed to parse CISA KEV:', error);
      return [];
    }
  }

  /**
   * MITRE ATT&CK GitHub Commits Parser
   */
  private async parseMITRECommits(data: string): Promise<FeedItem[]> {
    try {
      const commits = JSON.parse(data);

      return commits.slice(0, 5).map((commit: any) => ({
        id: this.generateId(`mitre-commit-${commit.sha}`),
        title: `MITRE ATT&CK Update: ${commit.commit.message.split('\n')[0]}`,
        content: commit.commit.message,
        url: commit.html_url,
        publishedAt: new Date(commit.commit.author.date)
      }));
    } catch (error) {
      console.error('Failed to parse MITRE commits:', error);
      return [];
    }
  }

  /**
   * NVD CVE Feed Parser
   */
  private async parseNVD(data: string): Promise<FeedItem[]> {
    try {
      const json = JSON.parse(data);
      const cves = json.vulnerabilities || [];

      return cves.map((item: any) => {
        const cve = item.cve;
        return {
          id: this.generateId(`nvd-${cve.id}`),
          title: `${cve.id}: ${cve.descriptions[0]?.value || 'No description'}`,
          content: JSON.stringify(cve.metrics),
          url: `https://nvd.nist.gov/vuln/detail/${cve.id}`,
          publishedAt: new Date(cve.published)
        };
      });
    } catch (error) {
      console.error('Failed to parse NVD feed:', error);
      return [];
    }
  }

  /**
   * Sigma GitHub Commits Parser
   */
  private async parseSigmaCommits(data: string): Promise<FeedItem[]> {
    try {
      const commits = JSON.parse(data);

      return commits.slice(0, 5).map((commit: any) => ({
        id: this.generateId(`sigma-commit-${commit.sha}`),
        title: `New Sigma Rules: ${commit.commit.message.split('\n')[0]}`,
        content: commit.commit.message,
        url: commit.html_url,
        publishedAt: new Date(commit.commit.author.date)
      }));
    } catch (error) {
      console.error('Failed to parse Sigma commits:', error);
      return [];
    }
  }

  /**
   * Fetch data from URL
   */
  private async fetchURL(url: string): Promise<string> {
    return new Promise((resolve, reject) => {
      https.get(url, (res) => {
        let data = '';
        res.on('data', chunk => data += chunk);
        res.on('end', () => resolve(data));
      }).on('error', reject);
    });
  }

  /**
   * Collect from all enabled sources
   */
  async collectAll(): Promise<void> {
    console.log('[Multi-Source Collector] Starting collection from all sources...');

    for (const source of this.sources.filter(s => s.enabled)) {
      try {
        console.log(`[Multi-Source Collector] Fetching ${source.name}...`);
        
        const data = await this.fetchURL(source.url);
        const items = await source.parser.call(this, data);
        
        let newCount = 0;
        for (const item of items) {
          const isNew = await this.insertFeedItem(item, source.id);
          if (isNew) {
            newCount++;
            await this.createJob(item.id, 'threat_analysis');
          }
        }

        console.log(`[Multi-Source Collector] ${source.name}: ${newCount} new items`);
      } catch (error) {
        console.error(`[Multi-Source Collector] Error fetching ${source.name}:`, error);
      }
    }

    console.log('[Multi-Source Collector] Collection complete');
  }

  private async insertFeedItem(item: FeedItem, source: string): Promise<boolean> {
    const stmt = this.db.prepare(`
      INSERT OR IGNORE INTO feed_items (
        id, feed_source, title, content, url, published_at, status
      ) VALUES (?, ?, ?, ?, ?, ?, 'pending')
    `);

    const result = stmt.run(
      item.id,
      source,
      item.title,
      item.content,
      item.url,
      item.publishedAt.toISOString()
    );

    return result.changes > 0;
  }

  private async createJob(feedItemId: string, jobType: string): Promise<string> {
    const jobId = `job_${Date.now()}_${Math.random().toString(36).substring(7)}`;
    
    this.db.prepare(`
      INSERT INTO jobs (id, job_type, status, priority, payload, created_at)
      VALUES (?, ?, 'pending', 5, ?, CURRENT_TIMESTAMP)
    `).run(jobId, jobType, JSON.stringify({ feed_item_id: feedItemId }));

    this.db.prepare(`UPDATE feed_items SET job_id = ? WHERE id = ?`)
      .run(jobId, feedItemId);

    return jobId;
  }

  private generateId(input: string): string {
    return createHash('sha256').update(input).digest('hex').substring(0, 16);
  }
}
