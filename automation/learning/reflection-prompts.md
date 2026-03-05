# Reflection & Learning Prompts for Autonomous Detection Engineering

These prompts should be integrated into the subagents (particularly orchestrator) to enable metacognitive self-improvement.

## Micro-Level Reflection (Per Detection)

**When**: After each detection creation and validation cycle

**Prompt Template**:
```markdown
Reflect on this detection creation cycle:

**Detection**: {detection_name}
**Technique**: {mitre_id}
**Validation Status**: {PASSED/FAILED}
**Atomic Test**: {atomic_id}
**Iterations Required**: {iteration_count}
**Time to Complete**: {duration_minutes} minutes

Analyze:
1. What worked well in this detection?
2. What challenges did you encounter?
3. What SPL patterns proved effective for this technique type?
4. What can be reused for similar detections?

Use the security-detections MCP to record your insights:
- Call `log_decision` to document WHY you made specific choices
- Call `add_learning` to capture reusable patterns

Learning Type: detection_pattern
Title: {technique_id} Detection Pattern
```

## Meso-Level Reflection (Per Technique Category)

**When**: After processing 5-10 detections of the same technique category (e.g., T1003.*)

**Prompt Template**:
```markdown
Analyze detection patterns for {technique_category}:

**Detections Created**: {count}
**Validation Rate**: {pass_rate}%
**Common Data Sources**: {data_sources}
**Technique Category**: {category_name}

Cross-Detection Analysis:
1. What SPL patterns are common across this category?
2. What data sources are most effective?
3. What false positive patterns emerged?
4. What baseline or threshold logic is needed?

Create a technique category learning entry:
- Call `add_learning` with type: technique_category_pattern
- Title: {category} Detection Best Practices
- Include: Common SPL fragments, FP mitigation strategies
```

## Macro-Level Reflection (Detection Engineering Strategy)

**When**: Weekly or after 50+ detections

**Prompt Template**:
```markdown
Strategic Detection Engineering Review:

**Period**: {start_date} to {end_date}
**Detections Created**: {total_count}
**Validation Success Rate**: {overall_pass_rate}%
**Coverage Improvement**: {coverage_delta}%

**Top Techniques Covered**: 
- {top_5_techniques}

**Most Challenging**: 
- {failed_techniques_and_reasons}

Strategic Questions:
1. What has improved about our detection creation process?
2. What types of detections still fail validation frequently?
3. Should we add new pipeline steps based on failure patterns?
4. Are there data source gaps limiting our effectiveness?

Update global strategy:
- Call `log_decision` with type: strategy_evolution
- Document recommended pipeline improvements
- Flag data source requirements for security_content repo
```

## Failure Analysis Reflection

**When**: After any detection validation failure

**Prompt Template**:
```markdown
Analyze this validation failure:

**Detection**: {detection_name}
**Technique**: {mitre_id}
**Failure Type**: {schema_fail/validation_fail/no_atomic/spl_error}
**Error Details**: {error_message}

Root Cause Analysis:
1. What was the immediate cause of failure?
2. What underlying issue led to this?
3. Could this failure have been prevented earlier in the pipeline?
4. Should we add a new validation step?

Improvement Actions:
- If schema failure: Update detection-engineer prompt with this rule
- If validation failure: Improve SPL logic or atomic test selection
- If systemic: Propose new pipeline step

Record the learning:
- Call `log_decision` with failure analysis
- Call `log_pipeline_improvement` if new step recommended
```

## Pattern Learning Integration

**Example**: After reflecting on T1003.001 (LSASS Credential Dumping)

```typescript
// Call this after successful validation
await mcpTools.add_learning({
  learning_type: 'detection_pattern',
  title: 'T1003.001 LSASS Credential Dumping SPL Pattern',
  insight: `
    Successful T1003.001 detections use this pattern:
    
    1. Data Model: Endpoint.Processes
    2. Key Fields: 
       - process_name (procdump.exe, Taskmgr.exe, etc.)
       - process (command line with lsass)
       - parent_process_name (context matters)
    3. Filter Logic:
       - Check for known dumping tools
       - Look for lsass.exe as target
       - Exclude legitimate backup software
    4. Common FPs:
       - Windows Defender scanning
       - Backup software (Veeam, etc.)
       - Add filter macro for tuning
    
    Validation: Atomic test T1003.001-1 (procdump) reliably triggers
  `,
  context: JSON.stringify({
    technique: 'T1003.001',
    validation_rate: 0.95,
    common_tools: ['procdump', 'mimikatz', 'taskmgr'],
    atomic_tests: ['T1003.001-1', 'T1003.001-2']
  })
});
```

## Decision Logging Integration

**Example**: After choosing between multiple detection approaches

```typescript
await mcpTools.log_decision({
  decision_type: 'detection_approach',
  context: 'T1003.001 credential dumping detection',
  decision: 'Use process_name filtering rather than handle access events',
  reasoning: `
    Considered two approaches:
    1. Process creation (Sysmon EventID 1) - Filter on procdump.exe, etc.
    2. Process access (Sysmon EventID 10) - Filter on TargetImage=lsass.exe
    
    Chose #1 because:
    - More reliable in Attack Range (EventID 1 always collected)
    - Lower false positive rate (process names are specific)
    - Atomic tests generate process creation events
    - Attack Range default config captures this
    
    Trade-off: May miss handle-based attacks without process creation
    Future: Create separate detection for EventID 10 coverage
  `
});
```

## Campaign Tracking Integration

**Example**: After processing STORM-0501 threat intel

```typescript
await mcpTools.track_campaign_observation({
  campaign_id: 'storm-0501',
  observation_type: 'technique',
  content: JSON.stringify({
    technique: 'T1003.001',
    tool: 'procdump.exe',
    context: 'Observed in January 2026 CISA alert',
    detection_created: 'windows_lsass_memory_dump_storm_0501.yml'
  }),
  source: 'https://www.cisa.gov/news-events/cybersecurity-advisories/aa24-131a'
});
```
