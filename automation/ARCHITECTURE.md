# Architecture Deep Dive - Autonomous Detection Platform 3.0

Technical architecture documentation for the face-melting autonomous detection engineering system.

## Core Innovation: Cursor Subagents

Instead of building custom LangGraph orchestration, we leverage Cursor's native subagent system for zero-infrastructure multi-agent coordination.

### Why Cursor Subagents?

| Custom LangGraph | Cursor Subagents |
|-----------------|------------------|
| Build TypeScript orchestration | Use built-in Task tool |
| Manage state machine manually | Context preserved automatically |
| Build agent-to-agent protocol | Native `/agent-name` invocation |
| Custom checkpointing | Built-in resume with agent IDs |
| Build tool integration | **Inherit all MCPs automatically** |
| Weeks of infrastructure work | **Ready TODAY** |

**The Win**: All MCPs (security-detections, splunk, mitre-attack, atomic-red-team) automatically available to every subagent.

---

## System Architecture

```
┌─────────────────────────────────────────────────────────────────────────────┐
│                           AUTONOMOUS PIPELINE                               │
├─────────────────────────────────────────────────────────────────────────────┤
│                                                                             │
│  ┌──────────────┐                                                           │
│  │ Threat Feeds │                                                           │
│  │ (RSS/JSON)   │                                                           │
│  └──────┬───────┘                                                           │
│         │                                                                   │
│         ▼                                                                   │
│  ┌──────────────┐     ┌────────────────┐                                   │
│  │ Feed Parser  │────►│  Job Queue     │                                   │
│  │  (Normalize) │     │  (SQLite)      │                                   │
│  └──────────────┘     └────────┬───────┘                                   │
│                               │                                            │
│                               ▼                                            │
│                        ┌──────────────┐                                     │
│                        │ Queue Watcher│                                     │
│                        │ (autonomous- │                                     │
│                        │   loop.ts)   │                                     │
│                        └──────┬───────┘                                     │
│                               │                                            │
│                               ▼                                            │
│                        ┌──────────────────┐                                 │
│                        │  /orchestrator   │◄─── Cursor Subagent             │
│                        └──────┬───────────┘                                 │
│                               │                                            │
│      ┌────────────────────────┼────────────────────────┐                   │
│      │                        │                        │                   │
│      ▼                        ▼                        ▼                   │
│ ┌──────────┐            ┌──────────┐            ┌──────────┐              │
│ │   /cti-  │            │/detection│            │/coverage-│              │
│ │ analyst  │            │-engineer │            │ analyzer │              │
│ └────┬─────┘            └────┬─────┘            └────┬─────┘              │
│      │                       │                       │                    │
│      └───────────────────────┼───────────────────────┘                    │
│                              │                                            │
│                              ▼                                            │
│                       ┌──────────────┐                                     │
│                       │  /qa-reviewer │                                     │
│                       └──────┬───────┘                                     │
│                              │                                            │
│                              ▼ (contentctl pass)                          │
│                       ┌──────────────┐                                     │
│                       │  /atomic-    │                                     │
│                       │  executor    │                                     │
│                       └──────┬───────┘                                     │
│                              │                                            │
│                              ▼ (background)                               │
│                   ┌──────────────────────┐                                 │
│                   │   Attack Range       │                                 │
│                   │   Execute Atomic     │                                 │
│                   └──────────┬───────────┘                                 │
│                              │                                            │
│                              ▼ (wait 2 min)                               │
│                       ┌──────────────┐                                     │
│                       │  /splunk-    │                                     │
│                       │  validator   │                                     │
│                       └──────┬───────┘                                     │
│                              │                                            │
│                   ┌──────────┴──────────┐                                  │
│                   │                     │                                  │
│                   ▼ (PASS)              ▼ (FAIL)                           │
│            ┌──────────────┐      ┌──────────────┐                          │
│            │ /data-dumper │      │  Retry with  │                          │
│            └──────┬───────┘      │    fixes     │                          │
│                   │              └──────────────┘                          │
│                   ▼                                                        │
│            ┌──────────────┐                                                 │
│            │ /pr-stager   │                                                 │
│            └──────┬───────┘                                                 │
│                   │                                                        │
│                   ▼                                                        │
│            ┌──────────────┐                                                 │
│            │  /verifier   │                                                 │
│            └──────┬───────┘                                                 │
│                   │                                                        │
│                   ▼                                                        │
│            ┌──────────────┐                                                 │
│            │   Notify     │                                                 │
│            │   Humans     │                                                 │
│            └──────────────┘                                                 │
│                                                                             │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## Data Flow

### 1. Threat Intelligence Ingestion

```
CISA RSS Feed
    ↓
feedparser
    ↓
Normalize to FeedItem
    ↓
INSERT INTO feed_items
    ↓
CREATE job (threat_analysis)
```

### 2. Job Queue Processing

```
Queue Watcher (autonomous-loop.ts)
    ↓
SELECT * FROM jobs WHERE status='pending'
    ↓
Invoke /orchestrator subagent
    ↓
Update job status → 'running'
```

### 3. Orchestrator Workflow

```
/orchestrator receives feed_item
    ↓
Invoke /cti-analyst → Extract TTPs
    ↓
Invoke /coverage-analyzer → Find gaps
    ↓
FOR EACH gap:
    Invoke /detection-engineer → Create YAML
    Invoke /qa-reviewer → Validate schema
    IF validation fails: Retry with fixes
    ↓
    Invoke /atomic-executor → Run test (background)
    Invoke /splunk-validator → Validate detection
    IF fails: Debug and refine SPL
    ↓
    Invoke /data-dumper → Export attack data
    Invoke /pr-stager → Stage dual PRs
    ↓
Invoke /verifier → Confirm completion
    ↓
Return results to orchestrator
    ↓
Update job status → 'completed'
```

---

## Database Schema

### Core Tables

#### jobs
- Stores all work items
- Status: pending → running → completed/failed
- Supports retry logic
- Chaining via parent_job_id

#### feed_items
- Ingested threat intelligence
- Linked to jobs via job_id
- Status tracking

#### validation_results
- Tracks atomic test validation outcomes
- Links detection to technique
- Historical validation data

#### campaign_observations
- Temporal campaign tracking
- Threat actor evolution
- Multi-source correlation

### Indexes

Optimized queries for:
- Job queue polling: `idx_jobs_status_priority`
- Feed processing: `idx_feed_items_status`
- Validation lookup: `idx_validation_detection`
- Campaign analysis: `idx_campaign_obs_campaign`

---

## Subagent Specialization

### CTI Analyst (Threat Intelligence)

**Specialization**: Parsing unstructured threat reports

**Tools Used**:
- mitre-attack MCP (validate techniques, get actor TTPs)
- security-detections MCP (check coverage)

**Output**: Structured TTP list with confidence scores

**Context Size**: Medium (threat reports can be long)

### Detection Engineer (SPL Writing)

**Specialization**: Creating detection YAMLs

**Tools Used**:
- security-detections MCP (patterns, search, data sources)

**Output**: Complete YAML file

**Context Size**: Small (focused on one detection)

**Critical**: Must follow contentctl schema exactly

### Atomic Executor (Attack Simulation)

**Specialization**: Finding and running atomic tests

**Tools Used**:
- Shell (Attack Range commands)
- Atomic Red Team MCP (query tests)

**Output**: Execution status and log locations

**Context Size**: Small

**Mode**: Background (`is_background: true`) - doesn't block orchestrator

### Splunk Validator (Detection Testing)

**Specialization**: Verifying detections fire

**Tools Used**:
- Splunk MCP (run_detection, search, list_indices)

**Output**: PASS/FAIL with evidence

**Context Size**: Medium (includes search results)

**Critical**: Must wait for log ingestion before validating

### Verifier (Quality Assurance)

**Specialization**: Skeptical validation

**Tools Used**:
- Read (check files)
- Shell (contentctl validate)
- Splunk MCP (re-run detections)

**Output**: VERIFIED or FAILED with evidence

**Context Size**: Small

**Model**: Fast (simple checks, doesn't need deep reasoning)

---

## MCP Tool Inheritance

All subagents automatically inherit these MCPs:

### security-detections (70+ tools)
- search, get_by_id, list_all
- analyze_coverage, identify_gaps
- get_patterns, add_learning
- log_decision, create_entity

### mitre-attack (30+ tools)
- get_technique, get_group_techniques
- analyze_coverage, find_group_gaps
- generate_coverage_layer

### user-splunk-mcp (7 tools)
- search, run_detection, export_dump
- list_indices, list_sourcetypes

### atomic-red-team-mcp (tools vary)
- query_atomics, execute_atomic

This is the power of the MCP architecture - **zero integration work required**.

---

## Self-Improvement Mechanisms

### Pattern Learning

After N successful detections of technique T:

```sql
-- Query patterns
SELECT * FROM kg_learnings 
WHERE learning_type = 'detection_pattern' 
AND context LIKE '%T1003%';
```

Detection engineer queries patterns before creating new detections:

```
/detection-engineer queries: get_similar_detection_patterns(technique_id='T1003.001')
Returns: Common SPL fragments, data model usage, FP filters
Applies: Proven patterns to new detection
```

### Pipeline Evolution

After failures, system can propose new pipeline steps:

```typescript
// Orchestrator learns: "Check for similar detections before creating"
// Next time, adds deduplication step automatically

if (learnings.includes('deduplication_needed')) {
  // Insert new step into workflow
  workflow.insertAfter('threat_analysis', 'dedup_check');
}
```

### Temporal Campaign Memory

Track threat actors over time:

```sql
-- Example: STORM-0501 observations
SELECT observed_at, observation_type, content 
FROM campaign_observations 
WHERE campaign_id = 'storm-0501' 
ORDER BY observed_at;

-- Results:
-- 2024-01: Initial access (T1566.001)
-- 2024-02: Lateral movement (T1021.001)
-- 2024-03: Credential dumping (T1003.001)
-- 2024-04: Ransomware (T1486) <-- NEW GAP IDENTIFIED
```

System proactively creates T1486 detection for STORM-0501.

---

## Scalability Considerations

### Current Scale (Single Instance)

- **Feeds**: ~10 sources, ~100 items/day
- **Jobs**: ~50 detections/week
- **Database**: Single SQLite file (<100MB)
- **Processing**: Sequential job processing

**Sufficient for**: Single analyst/team, moderate feed volume

### Future Scale (Distributed)

If needed:

1. **Multiple Workers**: Run multiple autonomous-loop instances
2. **Database**: Migrate SQLite → PostgreSQL for concurrent writes
3. **Message Queue**: Add Redis for job distribution
4. **Load Balancer**: Distribute feed collection

**Required when**: >500 detections/week, >20 feeds, multiple teams

---

## Security Considerations

### Secrets Management

**Current**: Environment variables

**Production**: Use secrets manager

```bash
# DO NOT commit these
export GITHUB_TOKEN="ghp_..."
export SLACK_WEBHOOK_URL="https://hooks.slack.com/..."
export SPLUNK_PASSWORD="..."
```

### GitHub Permissions

Subagents need:
- Repository: Read
- Pull Requests: Write
- Contents: Write (for branches, not main)

Configure fine-grained PAT with these permissions.

### Database Access

Ensure `detections.db` has proper permissions:

```bash
chmod 600 $DETECTIONS_DB_PATH
chown $USER:$USER $DETECTIONS_DB_PATH
```

---

## Integration Points

### With Existing MCPs

The system integrates with:

1. **security-detections MCP**
   - Detection search and analysis
   - Pattern extraction
   - Knowledge graph (tribal knowledge)

2. **mitre-attack MCP**
   - Technique lookup and validation
   - Threat actor profiling
   - Coverage layer generation

3. **Splunk MCP**
   - Detection execution
   - Data export
   - Index/sourcetype discovery

4. **Atomic Red Team MCP**
   - Atomic test lookup
   - Test execution (if enabled)

### With Attack Range

Attack Range Python API:

```python
# Simulate attacks
python attack_range.py simulate -e ART -te T1003.001 -t ar-win-ar-ar-0

# Dump attack data
python attack_range.py dump \
  --file_name output.log \
  --search 'index=win' \
  --earliest 2h

# Replay data
python attack_range.py replay \
  --file_name dataset.log \
  --index test \
  --sourcetype test
```

### With GitHub

Via `gh` CLI:

```bash
# Create PR
gh pr create \
  --repo splunk/security_content \
  --title "Detection: Windows LSASS Memory Dump" \
  --body "Automated detection submission..." \
  --draft

# Link PRs
gh pr comment 123 \
  --body "Related attack_data PR: splunk/attack_data#456"
```

---

## Performance Optimization

### Parallel Subagent Execution

Orchestrator can invoke multiple subagents simultaneously:

```typescript
// Sequential (slow)
const analysis = await invoke('/cti-analyst', report);
const gaps = await invoke('/coverage-analyzer', analysis.techniques);

// Parallel (fast)
const [analysis, existingPatterns] = await Promise.all([
  invoke('/cti-analyst', report),
  invoke('security-detections:get_patterns', { technique })
]);
```

### Context Management

- **Background subagents** (atomic-executor): Don't block orchestrator
- **Fast model** (verifier): Use for simple validation checks
- **Context pruning**: Large search results filtered before return

### Database Optimization

```sql
-- Vacuum regularly
PRAGMA vacuum;

-- Analyze for query optimization
PRAGMA analyze;

-- Increase cache
PRAGMA cache_size = -64000;  -- 64MB cache
```

---

## Failure Modes & Recovery

### Subagent Failure

**Scenario**: /detection-engineer crashes

**Recovery**:
1. Job status remains 'running'
2. Timeout after 30 minutes
3. Job status → 'pending'
4. Retry counter incremented
5. Max 3 retries before marking 'failed'

### Database Corruption

**Scenario**: SQLite corruption

**Recovery**:
1. Stop all services
2. Restore from daily backup
3. Replay failed jobs

### Attack Range Unavailable

**Scenario**: Attack Range down during validation

**Recovery**:
1. /atomic-executor reports failure
2. Job queued for retry
3. Human notified
4. Optional: Skip validation, stage PR anyway with note

### GitHub Rate Limiting

**Scenario**: Too many PR staging requests

**Recovery**:
1. /pr-stager catches rate limit error
2. Job queued for retry with backoff
3. Reduce PR creation frequency

---

## Monitoring & Observability

### Key Metrics

```sql
-- Jobs processed per hour
SELECT 
  strftime('%Y-%m-%d %H', completed_at) as hour,
  COUNT(*) as jobs_completed
FROM jobs 
WHERE status = 'completed'
GROUP BY hour
ORDER BY hour DESC
LIMIT 24;

-- Validation success rate
SELECT 
  status,
  COUNT(*) as count,
  ROUND(COUNT(*) * 100.0 / SUM(COUNT(*)) OVER (), 2) as percentage
FROM validation_results
WHERE validation_date > date('now', '-7 days')
GROUP BY status;

-- Coverage improvement
SELECT 
  assessed_at,
  coverage_percentage,
  coverage_percentage - LAG(coverage_percentage) OVER (ORDER BY assessed_at) as delta
FROM campaign_coverage
ORDER BY assessed_at DESC
LIMIT 10;
```

### Log Analysis

```bash
# Errors in last hour
grep ERROR automation/logs/autonomous-loop.log | tail -20

# Validation failures
grep "FAILED" automation/logs/autonomous-loop.log | wc -l

# Average job time
awk '/Starting job/ {start=$1} /completed successfully/ {print $1-start}' automation/logs/autonomous-loop.log | awk '{sum+=$1; n++} END {print sum/n}'
```

---

## Cost Analysis

### Token Usage Estimation

Per detection creation (full pipeline):

| Subagent | Tokens | Model |
|----------|--------|-------|
| /cti-analyst | ~5K | inherit |
| /coverage-analyzer | ~3K | inherit |
| /detection-engineer | ~10K | inherit |
| /qa-reviewer | ~2K | inherit |
| /atomic-executor | ~5K | inherit (background) |
| /splunk-validator | ~5K | inherit |
| /data-dumper | ~3K | inherit |
| /pr-stager | ~5K | inherit |
| /verifier | ~2K | fast |
| **Total** | **~40K tokens** | per detection |

At $3/million input tokens (Claude Sonnet 4):
- Per detection: $0.12
- 100 detections/week: $12/week
- Annual: ~$600

**This is CHEAP for a Detection Engineering Team in a Box**.

### Optimization Strategies

1. **Use fast model** for simple tasks (verifier)
2. **Background mode** for long-running tasks (atomic-executor)
3. **Batch operations** where possible
4. **Cache patterns** in knowledge graph (avoid re-analysis)

---

## Extension Points

### Adding New Feeds

1. Create parser in `collectors/multi-source-collector.ts`
2. Add to `autonomous.yml` configuration
3. System automatically processes new items

### Adding New Subagents

1. Create `.cursor/agents/new-agent.md`
2. Define clear specialization
3. Cursor automatically loads it
4. Orchestrator can invoke it

### Adding New Job Types

1. Add to job_type enum
2. Create handler in autonomous-loop.ts
3. Orchestrator routes to appropriate subagent

---

## Comparison with Other Approaches

### vs. LangGraph

| Aspect | LangGraph | Cursor Subagents |
|--------|-----------|------------------|
| Setup Time | Weeks | **Hours** |
| State Management | Manual | **Automatic** |
| Tool Integration | Custom wrappers | **Inherited MCPs** |
| Debugging | Complex | **Simple (read .md files)** |
| Extensibility | Code changes | **Edit markdown** |

### vs. CrewAI

| Aspect | CrewAI | Cursor Subagents |
|--------|--------|------------------|
| Agent Definition | Python classes | **Markdown files** |
| Tool Access | Custom integrations | **Inherited MCPs** |
| IDE Integration | None | **Native Cursor** |
| Learning | External storage | **MCP knowledge graph** |

### vs. Monolithic Agent

| Aspect | Single Agent | Multi-Subagent |
|--------|-------------|----------------|
| Context Usage | Grows continuously | **Isolated per task** |
| Specialization | Generalist | **9 specialists** |
| Parallelization | Sequential | **Parallel execution** |
| Debugging | Hard to trace | **Clear agent boundaries** |

**Winner**: Cursor Subagents for this use case.

---

## Future Enhancements

### Phase 7: Advanced Intelligence (Future)

- **Agent-to-Agent Protocol (A2A)**: Coordinate with external agents (SOAR, MISP)
- **Cost-Aware MCTS Planning**: Optimize detection priorities under constraints
- **Advanced Reflection**: Meta-learning across detection categories
- **Autonomous Pipeline Evolution**: System adds new steps based on failures

### Phase 8: Enterprise Features (Future)

- **Multi-Tenant**: Separate queues per team
- **RBAC**: Role-based approval workflows
- **Audit Trail**: Complete lineage from threat → detection → PR
- **SLA Tracking**: Time-to-detection metrics per threat severity

---

## Conclusion

This architecture achieves:

✅ **Autonomous Operation** - Continuous threat intel processing  
✅ **Validated Detections** - Every detection tested via atomic execution  
✅ **Dual PRs** - Security_content + attack_data staged together  
✅ **Self-Improvement** - Learns from validation results  
✅ **Minimal Infrastructure** - Leverages Cursor's native capabilities  
✅ **Production Ready** - Human checkpoints, monitoring, graceful shutdown  

**This is a Detection Engineering Team in a Box.**
