# Security Detections MCP 3.0 - Autonomous Detection Engineering Platform

Transform threat intelligence into validated detections automatically using Cursor Subagents.

## What This Does

This system continuously:
1. **Ingests** threat intel from CISA, MITRE, vendor blogs
2. **Analyzes** for MITRE ATT&CK techniques and coverage gaps
3. **Creates** Splunk detection YAMLs matching repo conventions
4. **Validates** detections via Atomic Red Team tests in Attack Range
5. **Dumps** validated attack data for future testing
6. **Stages** dual DRAFT PRs to security_content and attack_data repos
7. **Learns** from validation results to improve over time

**No auto-merging. Human review required.**

---

## Architecture Overview

```
CISA/MITRE Feeds → Job Queue → Cursor Subagents → Validated Detections → Dual PRs (DRAFT)
                                      ↓
                            Attack Range Testing
                                      ↓
                              Splunk Validation
                                      ↓
                             Attack Data Dump
```

### Cursor Subagents (9 Specialists)

Located in `.cursor/agents/`:

| Subagent | Purpose |
|----------|---------|
| `orchestrator.md` | Main workflow coordinator |
| `cti-analyst.md` | Parse threat intel, extract TTPs |
| `detection-engineer.md` | Write SPL, create YAMLs |
| `coverage-analyzer.md` | Gap analysis |
| `atomic-executor.md` | Find/run atomic tests (background) |
| `splunk-validator.md` | Validate detections fire |
| `data-dumper.md` | Export attack data |
| `pr-stager.md` | Create dual draft PRs |
| `verifier.md` | Skeptical validator |

---

## Quick Start

### Prerequisites

1. **Detections MCP v2.x** installed and built (see [Setup Guide](../SETUP.md))

2. **Attack Range** configured and accessible (Splunk only):
   - Python environment with `attack_range.py`
   - AWS/local infrastructure deployed

3. **Splunk MCP** connected to Attack Range Splunk instance (Splunk only)

4. **Environment Variables**:
   ```bash
   export DETECTIONS_DB_PATH="$HOME/.cache/security-detections-mcp/detections.sqlite"
   export ATTACK_RANGE_PATH="/path/to/attack_range"
   export SLACK_WEBHOOK_URL="https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
   export GITHUB_TOKEN="ghp_your_token_here"
   ```

### Installation

1. **Apply database migrations**:
   ```bash
   sqlite3 $DETECTIONS_DB_PATH < automation/migrations/001_add_job_queue.sql
   ```

2. **Install dependencies**:
   ```bash
   cd automation
   npm install feedparser-promised better-sqlite3
   ```

3. **Verify subagents loaded**:
   ```bash
   ls -la .cursor/agents/
   # Should show: orchestrator.md, cti-analyst.md, etc.
   ```

### Manual Testing

Test individual subagents before running autonomous mode:

```bash
# In Cursor Chat:

# 1. Test CTI analysis
> /cti-analyst https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a

# 2. Test detection creation for a technique
> /detection-engineer Create detection for T1003.001 credential dumping

# 3. Test full pipeline
> /orchestrator "Process CISA alert about STORM-0501"
```

### Autonomous Mode

Run the autonomous loop to process feeds automatically:

```bash
# One-time feed collection
node automation/collectors/cisa-rss-collector.ts once

# Continuous feed collection (background process)
node automation/collectors/cisa-rss-collector.ts continuous &

# Start autonomous job processor
node automation/runners/autonomous-loop.ts
```

Or use the provided wrapper script:

```bash
./automation/scripts/start-autonomous.sh
```

---

## Configuration

Edit `automation/config/autonomous.yml`:

```yaml
feeds:
  cisa_alerts:
    enabled: true
    poll_interval: 3600  # 1 hour

agent:
  model: "claude-sonnet-4-20250514"
  human_approval_required:
    - pr_creation  # Require approval before staging PRs

outputs:
  slack:
    enabled: true
    channel: "#detection-engineering"
```

---

## Workflow Details

### Complete Threat-to-Detection Pipeline

```
┌─────────────────────────────────────────────────────────────────┐
│ 1. Feed Item Ingested (CISA alert, MITRE update, etc.)         │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 2. /cti-analyst: Extract TTPs, map to MITRE, identify priority │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 3. /coverage-analyzer: Check existing coverage, find gaps      │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    ┌────────┴────────┐
                    │ Gaps found?     │
                    └────────┬────────┘
                             │ YES
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 4. /detection-engineer: Create detection YAML                  │
│    • Check data source availability (Attack Range constraint)  │
│    • Match repo style patterns                                 │
│    • Generate SPL query                                        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 5. /qa-reviewer: Validate schema, naming, MITRE mapping        │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    ┌────────┴────────┐
                    │ contentctl pass?│
                    └────────┬────────┘
                             │ YES
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 6. /atomic-executor (background): Find & execute atomic test   │
│    • Query ART MCP for matching test                           │
│    • Execute via Attack Range: python attack_range.py simulate │
│    • Wait for completion                                       │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼ (wait 2 min for ingestion)
┌─────────────────────────────────────────────────────────────────┐
│ 7. /splunk-validator: Run detection via Splunk MCP             │
│    • Execute SPL query against ingested data                   │
│    • Verify results match expected fields                      │
└────────────────────────────┬────────────────────────────────────┘
                             │
                    ┌────────┴────────┐
                    │ Detection fires?│
                    └────────┬────────┘
                             │ YES
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 8. /data-dumper: Export attack data from Splunk                │
│    • Dump Sysmon, Security logs from test window               │
│    • Create attack_data YAML metadata                          │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 9. /fp-analyst: Assess false positive risk                     │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼ (if FP risk acceptable)
┌─────────────────────────────────────────────────────────────────┐
│ 10. /pr-stager: Create dual DRAFT PRs                          │
│     • security_content: detection YAML                         │
│     • attack_data: dataset YAML + logs                         │
│     • Cross-reference PRs                                      │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
┌─────────────────────────────────────────────────────────────────┐
│ 11. /verifier: Skeptically verify everything worked            │
│     • Files exist?                                             │
│     • contentctl validates?                                    │
│     • PRs are DRAFT?                                           │
│     • PRs reference each other?                                │
└────────────────────────────┬────────────────────────────────────┘
                             │
                             ▼
                    ┌────────────────┐
                    │ VERIFIED ✓     │
                    │ Notify humans  │
                    └────────────────┘
```

### If Validation Fails

The system automatically:
1. **Analyzes** failure root cause
2. **Suggests** SPL fixes to /detection-engineer
3. **Retries** up to 3 times
4. **Logs** failure patterns for future improvement
5. **Notifies** humans if max retries exceeded

---

## Human-in-the-Loop

Approval required for:
- **PR Creation** - Review before staging PRs
- **High Impact Detections** - Critical infrastructure detections
- **New Data Sources** - Detections requiring sources not in Attack Range
- **High FP Risk** - Detections likely to have many false positives

### Approve/Reject via CLI

```bash
# List pending approvals
node automation/hitl/approval-system.ts list

# Approve
node automation/hitl/approval-system.ts approve approval_xyz123

# Reject
node automation/hitl/approval-system.ts reject approval_xyz123 "Needs more tuning"
```

---

## Database Schema

Added to detections MCP SQLite:

### Jobs Table
```sql
CREATE TABLE jobs (
  id TEXT PRIMARY KEY,
  job_type TEXT NOT NULL,
  status TEXT DEFAULT 'pending',
  priority INTEGER DEFAULT 5,
  payload TEXT,  -- JSON
  result TEXT,   -- JSON
  ...
);
```

### Feed Items Table
```sql
CREATE TABLE feed_items (
  id TEXT PRIMARY KEY,
  feed_source TEXT NOT NULL,
  title TEXT NOT NULL,
  content TEXT,
  url TEXT,
  status TEXT DEFAULT 'pending',
  job_id TEXT,
  ...
);
```

### Campaign Observations Table
```sql
CREATE TABLE campaign_observations (
  id TEXT PRIMARY KEY,
  campaign_id TEXT NOT NULL,
  observed_at TEXT NOT NULL,
  observation_type TEXT NOT NULL,
  content TEXT NOT NULL,
  ...
);
```

See `automation/migrations/001_add_job_queue.sql` for full schema.

---

## Monitoring

### View Queue Status

```bash
sqlite3 $DETECTIONS_DB_PATH "
  SELECT status, COUNT(*) 
  FROM jobs 
  GROUP BY status;
"
```

### View Recent Detections

```bash
sqlite3 $DETECTIONS_DB_PATH "
  SELECT id, job_type, status, created_at 
  FROM jobs 
  WHERE job_type = 'detection_creation' 
  ORDER BY created_at DESC 
  LIMIT 10;
"
```

### View Feed Health

```bash
sqlite3 $DETECTIONS_DB_PATH "
  SELECT feed_source, status, COUNT(*) 
  FROM feed_items 
  WHERE ingested_at > datetime('now', '-24 hours')
  GROUP BY feed_source, status;
"
```

---

## Self-Improvement Features

### Reflection Layers

The system reflects on its performance at three levels:

1. **Micro** (per-detection): "Did this validation pass? Why?"
2. **Meso** (per-technique-category): "What patterns work for T1003.* detections?"
3. **Macro** (weekly): "What should we improve about the pipeline?"

All reflections stored in the MCP knowledge graph via:
- `log_decision` - Record WHY choices were made
- `add_learning` - Capture reusable patterns

### Pattern Learning

After 10 successful T1003.001 detections, the system learns:
- Common SPL patterns for credential dumping
- Best data sources (Sysmon EventID 1 vs 10)
- Effective false positive filters
- Reliable atomic tests

Future T1003.* detections automatically use these patterns.

---

## Deployment Modes

### Mode 1: Development (Manual Invocation)

Test subagents manually in Cursor:

```
> /cti-analyst <URL>
> /orchestrator "Create detection for T1003.001"
```

### Mode 2: Semi-Autonomous (Cron Jobs)

Run collectors periodically, process queue manually:

```bash
# Crontab:
0 */1 * * * node /path/to/automation/collectors/cisa-rss-collector.ts once
```

Then manually run autonomous loop when ready:

```bash
node automation/runners/autonomous-loop.ts
```

### Mode 3: Full Autonomous (Production)

Both collectors and processor run continuously:

```bash
# Terminal 1: Feed collection
node automation/collectors/cisa-rss-collector.ts continuous

# Terminal 2: Job processing
node automation/runners/autonomous-loop.ts

# Terminal 3: Approval monitor (cron or continuous)
watch -n 300 'node automation/hitl/approval-system.ts check-expired'
```

Use `systemd`, `pm2`, or Docker Compose for production deployment.

---

## Attack Range Integration

### Data Source Constraints

Detections are constrained to Attack Range-available sources:

| Platform | Sources |
|----------|---------|
| Windows | Sysmon, Windows Security 4688, PowerShell |
| Linux | Sysmon for Linux |
| Network | Zeek |
| EDR (optional) | CrowdStrike FDR |

If a technique requires unavailable data sources, the system:
1. Flags it during detection creation
2. Requests human approval
3. Suggests alternative approaches

### Validation Flow

```
Detection YAML → Find Atomic Test → Execute in Attack Range
                                           ↓
                                    Wait 2 minutes
                                           ↓
                        Run detection via Splunk MCP
                                           ↓
                   ┌────────────────────────┴────────────────────────┐
                   │                                                 │
                   ▼ (results > 0)                                   ▼ (no results)
              VALIDATED ✓                                       DEBUG & REFINE
                   │                                                 │
                   ▼                                                 │
            Dump attack data                                         │
                   │                                                 │
                   └─────────────────────────────────────────────────┘
                                      ↓
                              Stage dual PRs
```

---

## Notification Templates

Slack messages sent for:
- ✅ **Detection Validated** - With PR links
- ❌ **Validation Failed** - With debug info
- 🔍 **Coverage Gap** - Identified missing techniques
- 📦 **PRs Staged** - Batch of detections ready for review

Configure in `automation/config/autonomous.yml`:

```yaml
outputs:
  slack:
    webhook_url: "${SLACK_WEBHOOK_URL}"
    channel: "#detection-engineering"
    enabled: true
```

---

## Self-Improvement Example

After successfully validating 5 T1003.001 detections:

**System learns**:
```
Pattern: T1003.001 LSASS Credential Dumping
- Use Endpoint.Processes data model
- Filter on: process_name IN (procdump.exe, Taskmgr.exe)
- Filter on: process contains "lsass"
- Exclude: Windows Defender, backup software
- Atomic test: T1003.001-1 reliably triggers
- Validation rate: 95%
```

**Next T1003.001 detection**:
- System queries learned patterns via `get_similar_detection_patterns`
- Applies proven SPL fragments
- Validation passes on first attempt
- Quality measurably improves

---

## File Structure

```
automation/
├── README.md                      # This file
├── config/
│   └── autonomous.yml             # Configuration
├── migrations/
│   └── 001_add_job_queue.sql      # Database schema
├── collectors/
│   ├── cisa-rss-collector.ts      # CISA feed collector
│   └── multi-source-collector.ts  # All other sources
├── runners/
│   └── autonomous-loop.ts         # Job queue processor
├── notifications/
│   └── slack-notifier.ts          # Slack integration
├── hitl/
│   └── approval-system.ts         # Human approval system
├── learning/
│   └── reflection-prompts.md      # Reflection guides
└── scripts/
    ├── start-autonomous.sh        # Start all services
    └── stop-autonomous.sh         # Stop gracefully

.cursor/agents/
├── orchestrator.md                # Main coordinator
├── cti-analyst.md                 # Threat intel parsing
├── detection-engineer.md          # SPL/YAML creation
├── coverage-analyzer.md           # Gap analysis
├── atomic-executor.md             # Atomic test execution
├── splunk-validator.md            # Detection validation
├── data-dumper.md                 # Attack data export
├── pr-stager.md                   # GitHub PR staging
├── fp-analyst.md                  # False positive analysis
├── qa-reviewer.md                 # Quality assurance
└── verifier.md                    # Skeptical validator
```

---

## Success Metrics

Track these in the database:

| Metric | Target | Query |
|--------|--------|-------|
| Detection validation rate | >90% | `SELECT AVG(CASE WHEN status='passed' THEN 1.0 ELSE 0 END) FROM validation_results` |
| Schema compliance | 100% | `SELECT COUNT(*) FROM jobs WHERE job_type='detection_creation' AND error LIKE '%contentctl%'` |
| Time to detection | <4 hours | `SELECT AVG(julianday(completed_at) - julianday(created_at)) * 24 FROM jobs WHERE job_type='threat_analysis'` |
| Coverage improvement | Track over time | `SELECT assessed_at, coverage_percentage FROM campaign_coverage ORDER BY assessed_at` |

---

## Troubleshooting

### Subagent not found

**Problem**: `Error: Subagent 'orchestrator' not found`

**Solution**: Ensure `.cursor/agents/orchestrator.md` exists and has proper YAML frontmatter.

### Validation always fails

**Problem**: Detections fire 0 results in Splunk

**Causes**:
1. Logs not ingested (wait longer)
2. Wrong sourcetype/index
3. SPL logic error
4. Atomic test didn't execute

**Debug**:
```bash
# Check if atomic ran
python attack_range.py show

# Check Splunk indices
# Via Splunk MCP: list_indices()

# Check recent logs
# Via Splunk MCP: search("index=win | head 10")
```

### Job queue stuck

**Problem**: Jobs remain in 'pending' status

**Solution**: Check autonomous loop is running:
```bash
ps aux | grep autonomous-loop
```

Restart if needed:
```bash
pkill -f autonomous-loop
node automation/runners/autonomous-loop.ts &
```

---

## What Makes This "Face-Melting"

| Basic Automation | This System |
|-----------------|-------------|
| Creates YAML | Creates, validates, tests, dumps data, stages PRs |
| One agent | 9 specialized Cursor Subagents |
| Hope it works | **Proves it works** via atomic testing |
| Manual testing | Automated atomic → Splunk validation |
| Point-in-time | Temporal campaign memory |
| Static pipeline | Self-improving via reflection |

This is a **Detection Engineering Team in a Box** that learns and improves over time.

---

## Next Steps

1. **Phase 1**: Test subagents manually via Cursor chat
2. **Phase 2**: Run collectors once, verify feed items ingested
3. **Phase 3**: Process one feed item manually via /orchestrator
4. **Phase 4**: Enable autonomous loop for continuous operation
5. **Phase 5**: Monitor learning effectiveness after 50+ detections
6. **Phase 6**: Add additional feeds, tune configuration

---

## Contributing

All subagents are markdown files in `.cursor/agents/`. To improve a subagent:

1. Edit the `.md` file
2. Test changes manually
3. Commit improved version
4. System automatically uses updated prompts

Pattern improvements logged to knowledge graph are automatically applied by the detection-engineer subagent.

---

## Support & References

- **Cursor Subagents**: https://cursor.com/docs/context/subagents
- **Attack Range**: https://github.com/splunk/attack_range
- **Attack Data**: https://github.com/splunk/attack_data
- **Atomic Red Team**: https://github.com/redcanaryco/atomic-red-team
- **Security Content**: https://github.com/splunk/security_content
