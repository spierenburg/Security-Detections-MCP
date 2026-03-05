# Testing Guide - Autonomous Detection Platform 3.0

Comprehensive testing procedures for the face-melting autonomous detection system.

## Test Plan Overview

```
Phase 1: Unit Testing (Individual Subagents)
   ↓
Phase 2: Integration Testing (Subagent Coordination)
   ↓
Phase 3: End-to-End Testing (Full Pipeline)
   ↓
Phase 4: Validation Testing (Atomic + Splunk)
   ↓
Phase 5: Load Testing (Multiple Feeds)
```

---

## Phase 1: Unit Testing (Individual Subagents)

### Test 1.1: CTI Analyst

**Objective**: Verify threat intel parsing and TTP extraction

**Input**: CISA alert URL

```
/cti-analyst Analyze: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
```

**Expected Output**:
- Extracted MITRE techniques (e.g., T1003.001, T1021.001)
- Campaign/actor name identified
- Data source requirements listed
- Prioritized technique list

**Success Criteria**:
- [ ] At least 3 techniques extracted
- [ ] Uses security-detections MCP tools
- [ ] Structured output format

### Test 1.2: Coverage Analyzer

**Objective**: Verify gap analysis works

**Input**: Technique set or threat actor

```
/coverage-analyzer What are the detection gaps for APT29?
```

**Expected Output**:
- Current coverage percentage
- List of missing techniques
- Prioritized gap recommendations
- (Optional) Navigator layer JSON

**Success Criteria**:
- [ ] Queries security-detections MCP
- [ ] Queries mitre-attack MCP
- [ ] Returns actionable gap list

### Test 1.3: Detection Engineer

**Objective**: Verify YAML creation follows schema

**Input**: Technique ID and description

```
/detection-engineer Create detection for T1003.001 credential dumping using procdump.exe
```

**Expected Output**:
- Complete detection YAML
- Proper `rba:` section (not in tags)
- Correct data source names
- Snake_case file name
- Filter macro present

**Success Criteria**:
- [ ] File created in detections/endpoint/
- [ ] `contentctl validate` passes
- [ ] Data sources match Attack Range available
- [ ] Uses security-detections patterns

### Test 1.4: QA Reviewer

**Objective**: Verify quality checks work

**Input**: Path to detection YAML

```
/qa-reviewer Review: detections/endpoint/windows_lsass_memory_dump.yml
```

**Expected Output**:
- APPROVED or NEEDS_REVISION
- Specific issues if any
- Quality checklist results

**Success Criteria**:
- [ ] Runs contentctl validate
- [ ] Checks naming conventions
- [ ] Verifies MITRE mappings

### Test 1.5: Verifier

**Objective**: Verify skeptical validation works

**Input**: Claimed completed detection workflow

```
/verifier Verify this detection workflow completed successfully: <workflow_details>
```

**Expected Output**:
- VERIFIED or FAILED
- Evidence for each checkpoint
- Specific issues if incomplete

**Success Criteria**:
- [ ] Actually checks file existence
- [ ] Actually runs contentctl
- [ ] Reports accurate status

---

## Phase 2: Integration Testing (Subagent Coordination)

### Test 2.1: Orchestrator → CTI Analyst → Coverage Analyzer

**Objective**: Verify agent-to-agent coordination

```
/orchestrator Analyze STORM-0501 campaign and identify detection gaps
```

**Expected Behavior**:
1. Orchestrator invokes /cti-analyst
2. Receives extracted TTPs
3. Orchestrator invokes /coverage-analyzer with TTPs
4. Receives gap analysis
5. Returns structured results

**Success Criteria**:
- [ ] Multiple subagents invoked in sequence
- [ ] Context passed between agents
- [ ] Final output comprehensive

### Test 2.2: Detection Creation → QA → Validation

**Objective**: Verify detection quality pipeline

```
/orchestrator Create and validate detection for T1059.001 PowerShell command execution
```

**Expected Behavior**:
1. Detection engineer creates YAML
2. QA reviewer validates schema
3. (If fails) Detection engineer fixes
4. Repeat until approved

**Success Criteria**:
- [ ] Iterative improvement works
- [ ] Schema errors caught and fixed
- [ ] Final YAML passes contentctl

---

## Phase 3: End-to-End Testing (Full Pipeline)

### Test 3.1: Threat Report to Staged PRs

**Objective**: Complete autonomous workflow

**Setup**:
1. Ensure Attack Range is running
2. Ensure Splunk MCP connected
3. GitHub authentication configured

**Execute**:
```
/orchestrator Process this CISA alert end-to-end: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
```

**Expected Phases**:
1. ✅ Intelligence Analysis
2. ✅ Coverage Gap Identification
3. ✅ Detection Creation
4. ✅ Schema Validation
5. ✅ Atomic Test Execution (background)
6. ✅ Splunk Validation
7. ✅ Attack Data Dump
8. ✅ Dual PR Staging
9. ✅ Verification

**Success Criteria**:
- [ ] All phases complete without manual intervention
- [ ] Detection fires on atomic test
- [ ] PRs staged to both repos (DRAFT status)
- [ ] PRs reference each other
- [ ] Attack data dumped correctly
- [ ] /verifier confirms everything worked

**Acceptance**: If ANY phase fails, the test fails.

### Test 3.2: Multiple Detections in Parallel

**Objective**: Test parallel processing

**Execute**:
```
/orchestrator Create detections for these techniques in parallel: T1003.001, T1003.002, T1003.003
```

**Expected Behavior**:
- Multiple /detection-engineer instances run in parallel
- Each follows full validation pipeline
- Results aggregated by orchestrator

**Success Criteria**:
- [ ] All 3 detections created
- [ ] At least 2/3 validate successfully
- [ ] PRs staged for validated detections

---

## Phase 4: Validation Testing (Atomic + Splunk)

### Test 4.1: Atomic Executor (Background Mode)

**Objective**: Verify atomic tests execute correctly

**Execute**:
```
/atomic-executor Execute T1003.001 atomic test in Attack Range
```

**Expected Behavior**:
- Finds atomic via ART MCP
- Executes via Attack Range
- Runs in background (returns immediately)
- Logs execution status
- Waits for completion

**Success Criteria**:
- [ ] Atomic test executes successfully
- [ ] Logs appear in Attack Range Splunk
- [ ] Agent reports completion

### Test 4.2: Splunk Validator

**Objective**: Verify detection validation works

**Prerequisites**:
- Atomic test just executed (Test 4.1)
- Detection YAML exists

**Execute**:
```
/splunk-validator Validate: detections/endpoint/windows_lsass_memory_dump.yml
```

**Expected Behavior**:
- Waits for log ingestion
- Runs detection via Splunk MCP
- Analyzes results
- Reports PASS/FAIL with evidence

**Success Criteria**:
- [ ] Detection returns > 0 results
- [ ] Expected fields populated
- [ ] Results correlate to atomic execution time

### Test 4.3: Data Dumper

**Objective**: Verify attack data export works

**Prerequisites**:
- Successful validation (Test 4.2)

**Execute**:
```
/data-dumper Dump attack data for T1003.001 from the last atomic test
```

**Expected Behavior**:
- Identifies time window
- Exports Sysmon logs
- Exports Security logs
- Creates dataset YAML
- Formats for attack_data repo

**Success Criteria**:
- [ ] Log files exported
- [ ] Dataset YAML valid format
- [ ] Files match attack_data repo structure

---

## Phase 5: Load Testing

### Test 5.1: Multiple Feed Items

**Objective**: Process multiple threat reports simultaneously

**Setup**:
```bash
# Insert 10 feed items manually
for i in {1..10}; do
  sqlite3 $DETECTIONS_DB_PATH "INSERT INTO feed_items (id, feed_source, title, content, url, status) VALUES ('test_$i', 'test', 'Test Item $i', 'Content', 'http://example.com', 'pending');"
done
```

**Execute**:
```bash
node automation/runners/autonomous-loop.ts
```

**Monitor**:
```bash
watch -n 5 'sqlite3 $DETECTIONS_DB_PATH "SELECT status, COUNT(*) FROM jobs GROUP BY status;"'
```

**Success Criteria**:
- [ ] All jobs eventually complete
- [ ] No database locks
- [ ] Reasonable processing time (<1 hour per job)

---

## Regression Testing

### Before Deploying Changes

1. **Test all subagents individually**
2. **Test orchestrator workflow**
3. **Test validation pipeline**
4. **Generate test report**

```bash
# Run regression test suite
npm run test:regression

# Expected: All tests pass
# If any fail, DO NOT deploy
```

---

## Known Issues & Workarounds

### Issue: Attack Range expensive to run continuously

**Workaround**: Use offline validation for initial testing

```yaml
# In autonomous.yml
attack_range:
  enabled: false  # Skip atomic validation during development
```

### Issue: GitHub rate limits

**Workaround**: Cache GitHub API responses

```typescript
// Add caching to github integration
const cache = new Map();
if (cache.has(url)) {
  return cache.get(url);
}
```

### Issue: Subagent context too large

**Symptom**: Subagent times out or truncates

**Fix**: Use fast model for exploration, break into smaller tasks

```markdown
---
model: fast  # Use faster model
---
```

---

## Performance Benchmarks

Target benchmarks for a healthy system:

| Operation | Target Time | Measured |
|-----------|-------------|----------|
| Feed collection | <30 seconds | ___ |
| Threat analysis | <5 minutes | ___ |
| Detection creation | <10 minutes | ___ |
| Atomic validation | <15 minutes | ___ |
| Full pipeline | <45 minutes | ___ |

If any operation consistently exceeds targets, investigate and optimize.

---

## Test Data

Sample CISA alerts for testing:

1. **STORM-0501**: https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a
2. **Scattered Spider**: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-320a
3. **BlackCat/ALPHV**: https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-353a

Sample techniques for testing:
- **T1003.001** - LSASS Memory
- **T1059.001** - PowerShell
- **T1021.001** - RDP
- **T1486** - Data Encrypted for Impact

---

## Acceptance Criteria

System is production-ready when:

- [ ] All 11 subagents load correctly
- [ ] Feed collection works for CISA
- [ ] Job queue processes items
- [ ] Detection creation follows schema (100% contentctl pass rate)
- [ ] Atomic validation works (>80% validation rate)
- [ ] Dual PRs stage correctly
- [ ] Human approval system works
- [ ] Learning system captures patterns
- [ ] No memory leaks after 24-hour run
- [ ] Graceful shutdown works

---

## Test Execution Log

Use this template to track test results:

```
Date: ___________
Tester: ___________

Phase 1 - Unit Tests:
  [ ] Test 1.1: CTI Analyst - PASS/FAIL
  [ ] Test 1.2: Coverage Analyzer - PASS/FAIL
  [ ] Test 1.3: Detection Engineer - PASS/FAIL
  [ ] Test 1.4: QA Reviewer - PASS/FAIL
  [ ] Test 1.5: Verifier - PASS/FAIL

Phase 2 - Integration Tests:
  [ ] Test 2.1: Agent Coordination - PASS/FAIL
  [ ] Test 2.2: Quality Pipeline - PASS/FAIL

Phase 3 - End-to-End:
  [ ] Test 3.1: Threat to PRs - PASS/FAIL
  [ ] Test 3.2: Parallel Processing - PASS/FAIL

Phase 4 - Validation:
  [ ] Test 4.1: Atomic Executor - PASS/FAIL
  [ ] Test 4.2: Splunk Validator - PASS/FAIL
  [ ] Test 4.3: Data Dumper - PASS/FAIL

Phase 5 - Load:
  [ ] Test 5.1: Multiple Feeds - PASS/FAIL

Notes:
_________________________________________
_________________________________________
_________________________________________
```
