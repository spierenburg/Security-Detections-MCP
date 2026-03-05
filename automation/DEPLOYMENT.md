# Deployment Guide - Autonomous Detection Platform 3.0

Complete deployment and integration instructions for the face-melting autonomous detection engineering system.

## Prerequisites Checklist

- [ ] Detections MCP v2.x installed and working
- [ ] Attack Range deployed and accessible
- [ ] Splunk MCP connected to Attack Range Splunk
- [ ] Atomic Red Team MCP configured
- [ ] MITRE ATT&CK MCP available
- [ ] GitHub CLI (`gh`) installed and authenticated
- [ ] Node.js 18+ installed
- [ ] Python 3.8+ with Attack Range dependencies

---

## Part 1: Database Setup

### 1.1 Locate Detections MCP Database

```bash
# Find the detections MCP installation
cd /Users/michhaag/Documents/GitHub/detections-mcp/

# Verify database exists
ls -la detections.db
```

### 1.2 Apply Migrations

```bash
# Set environment variable
export DETECTIONS_DB_PATH="/Users/michhaag/Documents/GitHub/detections-mcp/detections.db"

# Apply job queue schema
sqlite3 $DETECTIONS_DB_PATH < automation/migrations/001_add_job_queue.sql

# Verify tables created
sqlite3 $DETECTIONS_DB_PATH "SELECT name FROM sqlite_master WHERE type='table' AND name IN ('jobs', 'job_schedule', 'feed_items');"
```

Expected output:
```
jobs
job_schedule
feed_items
campaign_observations
campaign_coverage
validation_results
```

### 1.3 Backup Database

```bash
# Create backup before first run
cp $DETECTIONS_DB_PATH ${DETECTIONS_DB_PATH}.backup_$(date +%Y%m%d)
```

---

## Part 2: Subagent Installation

### 2.1 Verify Subagents Created

```bash
cd /Users/michhaag/Research/malware/GitHub/security_content/

# List subagents
ls -la .cursor/agents/
```

Expected files:
```
atomic-executor.md
coverage-analyzer.md
cti-analyst.md
data-dumper.md
detection-engineer.md
fp-analyst.md
orchestrator.md
pr-stager.md
qa-reviewer.md
splunk-validator.md
verifier.md
```

### 2.2 Test Subagent Loading

Open Cursor and in chat:

```
List available subagents
```

You should see all 11 subagents listed.

---

## Part 3: Attack Range Configuration

### 3.1 Verify Attack Range Deployment

```bash
cd $ATTACK_RANGE_PATH

# Check infrastructure status
python attack_range.py show

# Verify Splunk is accessible
curl -k https://<splunk-ip>:8000
```

### 3.2 Configure Environment Variables

Add to `~/.zshrc` or `~/.bashrc`:

```bash
# Autonomous Detection Platform
export DETECTIONS_DB_PATH="/Users/michhaag/Documents/GitHub/detections-mcp/detections.db"
export ATTACK_RANGE_PATH="/path/to/attack_range"
export ATTACK_DATA_DUMP_PATH="/path/to/attack_data_dumps"
export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
export GITHUB_TOKEN="ghp_your_token_here"
```

Reload:
```bash
source ~/.zshrc
```

---

## Part 4: Install Automation Components

### 4.1 Install Dependencies

```bash
cd automation/

# Install Node.js dependencies
npm install

# Verify installation
npm list
```

### 4.2 Create Required Directories

```bash
mkdir -p logs
mkdir -p data/dumps
mkdir -p data/prs
```

---

## Part 5: Initial Testing

### 5.1 Test Feed Collection (Manual)

```bash
# Run once to test
node collectors/cisa-rss-collector.ts once

# Check database
sqlite3 $DETECTIONS_DB_PATH "SELECT COUNT(*) FROM feed_items;"
sqlite3 $DETECTIONS_DB_PATH "SELECT title FROM feed_items LIMIT 5;"
```

### 5.2 Test Subagent Invocation (Cursor Chat)

In Cursor:

```
/cti-analyst Analyze this CISA alert: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
```

Expected behavior:
- Subagent loads with MCP tools
- Extracts MITRE techniques
- Checks coverage via security-detections MCP
- Returns structured analysis

### 5.3 Test Detection Creation (Manual)

```
/detection-engineer Create a detection for T1003.001 credential dumping via procdump
```

Expected behavior:
- Checks for duplicates
- Queries patterns
- Generates complete YAML
- File name is snake_case

### 5.4 Test Full Orchestration (End-to-End)

```
/orchestrator Process this threat report and create validated detections: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
```

Expected behavior:
- Invokes /cti-analyst
- Invokes /coverage-analyzer
- Invokes /detection-engineer
- Invokes /qa-reviewer
- (If Attack Range available) Invokes /atomic-executor
- (If Splunk MCP available) Invokes /splunk-validator
- Invokes /verifier
- Reports results

---

## Part 6: Autonomous Mode Deployment

### 6.1 Start Services

```bash
cd /Users/michhaag/Research/malware/GitHub/security_content/

# Start all components
./automation/scripts/start-autonomous.sh
```

This starts:
- Feed collector (background)
- Cron scheduler (background)
- Autonomous loop processor (background)

### 6.2 Monitor Logs

```bash
# In separate terminals:

# Terminal 1: Feed collector
tail -f automation/logs/feed-collector.log

# Terminal 2: Autonomous loop
tail -f automation/logs/autonomous-loop.log

# Terminal 3: Cron scheduler
tail -f automation/logs/cron-scheduler.log
```

### 6.3 Monitor Job Queue

```bash
# Watch queue activity
watch -n 5 'sqlite3 $DETECTIONS_DB_PATH "SELECT status, COUNT(*) FROM jobs GROUP BY status;"'
```

Expected output:
```
pending   | 5
running   | 1
completed | 23
```

---

## Part 7: Human-in-the-Loop Management

### 7.1 Enable Approval Notifications

Edit `automation/config/autonomous.yml`:

```yaml
outputs:
  slack:
    enabled: true
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#detection-engineering"
```

### 7.2 Process Approval Requests

```bash
# List pending approvals
node automation/hitl/approval-system.ts list

# Approve a PR staging request
node automation/hitl/approval-system.ts approve approval_xyz123

# Reject with reason
node automation/hitl/approval-system.ts reject approval_abc456 "Detection needs more tuning"
```

### 7.3 Set Up Approval Monitoring

Add to crontab:
```bash
crontab -e

# Check for expired approvals every 5 minutes
*/5 * * * * cd /path/to/security_content && node automation/hitl/approval-system.ts check-expired >> automation/logs/approval-monitor.log 2>&1
```

---

## Part 8: Production Hardening

### 8.1 Use Process Manager

Instead of running scripts directly, use `pm2`:

```bash
npm install -g pm2

# Start with pm2
pm2 start automation/collectors/cisa-rss-collector.ts --name feed-collector -- continuous
pm2 start automation/runners/autonomous-loop.ts --name autonomous-loop
pm2 start automation/runners/cron-scheduler.ts --name cron-scheduler -- start

# View status
pm2 list

# View logs
pm2 logs autonomous-loop

# Save configuration
pm2 save

# Enable startup on boot
pm2 startup
```

### 8.2 Configure Log Rotation

```bash
# /etc/logrotate.d/autonomous-detection
/path/to/security_content/automation/logs/*.log {
    daily
    rotate 14
    compress
    delaycompress
    missingok
    notifempty
}
```

### 8.3 Set Up Monitoring

Use existing monitoring tools:

```bash
# Prometheus metrics (future)
# Grafana dashboard (future)

# For now, basic monitoring:
watch -n 60 'node automation/runners/autonomous-loop.ts && echo "Status: $(date)"'
```

---

## Part 9: Docker Deployment (Optional)

### 9.1 Create Dockerfile

```dockerfile
FROM node:18-alpine

WORKDIR /app

# Copy automation components
COPY automation/ ./automation/
COPY .cursor/agents/ ./.cursor/agents/

# Install dependencies
RUN cd automation && npm install

# Set environment
ENV DETECTIONS_DB_PATH=/data/detections.db
ENV NODE_ENV=production

# Expose monitoring port (future)
EXPOSE 3000

# Start autonomous loop
CMD ["node", "automation/runners/autonomous-loop.ts"]
```

### 9.2 Docker Compose

```yaml
version: '3.8'

services:
  feed-collector:
    build: .
    command: node automation/collectors/cisa-rss-collector.ts continuous
    volumes:
      - ./data:/data
    environment:
      - DETECTIONS_DB_PATH=/data/detections.db
    restart: unless-stopped

  autonomous-loop:
    build: .
    command: node automation/runners/autonomous-loop.ts
    volumes:
      - ./data:/data
    environment:
      - DETECTIONS_DB_PATH=/data/detections.db
      - ATTACK_RANGE_PATH=/attack_range
    depends_on:
      - feed-collector
    restart: unless-stopped

  cron-scheduler:
    build: .
    command: node automation/runners/cron-scheduler.ts start
    volumes:
      - ./data:/data
    environment:
      - DETECTIONS_DB_PATH=/data/detections.db
    restart: unless-stopped
```

---

## Part 10: Verification

### 10.1 Verify Full Pipeline

After deployment, verify each component:

1. **Feed Collection**:
   ```bash
   sqlite3 $DETECTIONS_DB_PATH "SELECT COUNT(*) FROM feed_items WHERE ingested_at > datetime('now', '-1 hour');"
   ```
   Should return > 0 if feeds are active

2. **Job Creation**:
   ```bash
   sqlite3 $DETECTIONS_DB_PATH "SELECT COUNT(*) FROM jobs WHERE created_at > datetime('now', '-1 hour');"
   ```
   Should increase over time

3. **Detection Creation**:
   ```bash
   ls -la detections/endpoint/*.yml | tail -5
   ```
   Look for recently created files

4. **Validation Results**:
   ```bash
   sqlite3 $DETECTIONS_DB_PATH "SELECT * FROM validation_results ORDER BY validation_date DESC LIMIT 5;"
   ```

5. **PRs Staged**:
   ```bash
   gh pr list --repo splunk/security_content --state open --author @me
   gh pr list --repo splunk/attack_data --state open --author @me
   ```

---

## Troubleshooting

### Issue: Subagents not found

**Symptom**: `Error: Subagent 'orchestrator' not found`

**Cause**: Cursor hasn't loaded subagents from `.cursor/agents/`

**Fix**:
1. Restart Cursor
2. Verify files have `.md` extension
3. Check YAML frontmatter is valid

### Issue: Database locked

**Symptom**: `SQLite database is locked`

**Cause**: Multiple processes accessing database simultaneously

**Fix**:
1. Use `PRAGMA busy_timeout = 5000` in DB connections
2. Ensure only one autonomous loop running
3. Check for zombie processes: `ps aux | grep autonomous`

### Issue: No jobs processing

**Symptom**: Jobs stuck in 'pending' status

**Cause**: Autonomous loop not running

**Fix**:
```bash
# Check if running
ps aux | grep autonomous-loop

# Restart
./automation/scripts/stop-autonomous.sh
./automation/scripts/start-autonomous.sh
```

### Issue: Validations always fail

**Symptom**: All atomic tests fail validation

**Causes & Fixes**:
1. **Attack Range not running**: `python attack_range.py show`
2. **Splunk MCP not connected**: Check MCP connection in Cursor
3. **Wrong target specified**: Verify target in orchestrator
4. **Logs not ingesting**: Increase wait time in splunk-validator

---

## Performance Tuning

### For High Volume

Edit `automation/config/autonomous.yml`:

```yaml
agent:
  max_retries: 5  # More resilient

# Reduce polling for production
feeds:
  cisa_alerts:
    poll_interval: 7200  # 2 hours instead of 1
```

### For Low Volume / Testing

```yaml
feeds:
  cisa_alerts:
    poll_interval: 3600
    enabled: true
  
  # Disable high-volume feeds during testing
  vendor_blogs:
    enabled: false
```

---

## Monitoring Checklist

Daily:
- [ ] Check job queue status
- [ ] Review validation success rate
- [ ] Process pending approvals
- [ ] Check error logs

Weekly:
- [ ] Generate coverage report
- [ ] Review learning effectiveness
- [ ] Optimize slow detections
- [ ] Update feed configurations

Monthly:
- [ ] Database vacuum and optimization
- [ ] Archive old jobs
- [ ] Review campaign coverage evolution
- [ ] Update Attack Range infrastructure

---

## Success Metrics to Track

| Metric | Query | Target |
|--------|-------|--------|
| Detection validation rate | `SELECT AVG(CASE WHEN status='passed' THEN 1.0 ELSE 0 END) FROM validation_results WHERE validation_date > date('now', '-7 days')` | >90% |
| Time to detection | `SELECT AVG((julianday(completed_at) - julianday(created_at)) * 24) FROM jobs WHERE job_type='threat_analysis' AND completed_at > datetime('now', '-7 days')` | <4 hours |
| Schema compliance | Count contentctl failures | 100% pass |
| Coverage improvement | Compare campaign_coverage over time | Trending up |

---

## Rollback Procedure

If issues arise:

```bash
# 1. Stop all services
./automation/scripts/stop-autonomous.sh

# 2. Restore database backup
cp ${DETECTIONS_DB_PATH}.backup_YYYYMMDD $DETECTIONS_DB_PATH

# 3. Revert to manual mode
# Process feed items manually via /orchestrator
```

---

## Next Steps After Deployment

1. **Week 1**: Monitor closely, tune configurations
2. **Week 2**: Enable additional feeds (vendor blogs)
3. **Week 3**: Measure learning effectiveness
4. **Month 1**: Review metrics, optimize pipeline
5. **Month 2**: Consider multi-instance deployment

---

## Support

For issues or questions:
1. Check logs in `automation/logs/`
2. Query job queue status
3. Review subagent prompt files
4. Consult main README.md
