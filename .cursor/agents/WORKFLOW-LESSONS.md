# Agent Workflow Lessons Learned

**Last Updated**: 2026-02-02  
**Source**: Lotus Blossom Chrysalis Backdoor detection engineering workflow

---

## Critical Lessons Applied to All Agents/Skills

### 1. Pragmatic Testing is OK ✅

**Principle**: Don't need actual malware to validate detections. Focus on generating telemetry that matches detection logic.

**What Changed**:
- Updated `.claude/skills/atomic-red-team-testing/SKILL.md` with pragmatic philosophy
- Updated `.cursor/agents/atomic-executor.md` with simulation examples
- Updated `.claude/skills/detection-yaml-engineer/SKILL.md` to design testable detections
- Updated `.cursor/agents/orchestrator.md` Phase 4 with pragmatic testing note

**Example**: To test TinyCC shellcode detection, copy `cmd.exe` to `svchost.exe` and run with `-nostdlib -run` flags. Detection only checks process name + command line, so this generates identical telemetry.

---

### 2. Always Search Existing Content Before Creating ✅

**Principle**: Don't create duplicate detections. Use MCP to search existing content FIRST.

**What Changed**:
- Updated `.cursor/agents/orchestrator.md` with Phase 2.5: Search Existing Content (MANDATORY)
- Updated `.cursor/agents/detection-engineer.md` to require MCP search before creation
- Updated `.cursor/agents/qa-reviewer.md` to verify MCP search completed

**MCP Search Pattern**:
```
CallMcpTool(
  server="user-security-detections",
  toolName="search",
  arguments={"query": "behavior keywords", "limit": 20}
)

CallMcpTool(
  server="user-security-detections",
  toolName="list_by_mitre",
  arguments={"technique_id": "T1234"}
)
```

**Decision Criteria**:
- Create NEW if: Unique adversary tradecraft or specific tool/malware signature
- Tag EXISTING if: Generic technique coverage exists

---

### 3. Always Export Attack Data After Validation ✅

**Principle**: Every validated detection must have corresponding attack data exported and properly referenced.

**What Changed**:
- Updated `.cursor/agents/data-dumper.md` with mandatory export rule and path structure
- Updated `.cursor/agents/splunk-validator.md` to call data-dumper after success
- Updated `.cursor/agents/orchestrator.md` Phase 6 with detailed export workflow
- Updated `.cursor/agents/qa-reviewer.md` with attack data validation checklist

**Required Structure**:
```
$ATTACK_DATA_PATH/
  └── datasets/
      └── attack_techniques/
          └── <TECHNIQUE_ID>/          # e.g., T1136.001
              └── <campaign>/          # e.g., lotus_blossom_chrysalis, uat_8099
                  ├── windows-sysmon.log
                  ├── windows-security.log
                  └── dataset.yml
```

**GitHub URL Format**:
```yaml
tests:
  - name: True Positive Test
    attack_data:
      - data: https://media.githubusercontent.com/media/<your-org>/attack_data/master/datasets/attack_techniques/T1543.003/lotus_blossom_chrysalis/windows-system.log
```

---

### 4. Analytic Stories Must Be Concise ✅

**Principle**: Stories should be 17-19 lines total, not books. Straight to the point.

**What Changed**:
- Updated `.claude/skills/analytic-story-builder/SKILL.md` with strict length guidelines
- Updated `.cursor/agents/orchestrator.md` Phase 9 with concise story requirements
- Updated `.cursor/agents/qa-reviewer.md` to check story length

**Format**:
- `description`: 3-5 sentences describing detection approach
- `narrative`: 5-8 sentences covering threat background, attack flow, detection strategy
- **Total**: ~17-19 lines (NOT 200+ lines with multi-section headers)

**What NOT to Include**:
- Multi-section narratives with ## headers
- Bullet-point lists
- "Investigation Guidance" sections
- "Response Recommendations" sections
- "Coverage Limitations" sections

---

### 5. Validate Complete Workflow Before PR ✅

**Principle**: Never create PR until ALL validation steps complete.

**What Changed**:
- Updated `.cursor/agents/pr-stager.md` with mandatory pre-flight checklist (now platform-aware)

**Pre-Flight Checklist** (universal):
- [ ] Atomic tests executed successfully
- [ ] Detections validated in target SIEM (per `SIEM_PLATFORM`)
- [ ] Attack data exported to correct path
- [ ] MCP search completed
- [ ] Git branch follows naming convention

**Platform-specific additions**:
- Splunk: `contentctl validate` passes, dataset.yml created, analytic story concise
- Sentinel: KQL runs against workspace, entity mappings defined
- Elastic: EQL/TOML validates, risk score set
- Sigma: Converts to at least one backend

**If ANY item incomplete → DO NOT create PR**

---

## Common Mistakes That Are Now Prevented

### ❌ Old Behavior → ✅ New Behavior

1. **Created detections without checking existing content**
   - ✅ Now: Phase 2.5 requires MCP search before any detection creation

2. **Validated detections but forgot to export attack data**
   - ✅ Now: siem-validator/splunk-validator automatically calls data-dumper after success

3. **Exported data but GitHub URLs pointed to wrong paths**
   - ✅ Now: qa-reviewer validates URL structure matches campaign subdirectory

4. **Created 200+ line analytic stories with multi-section narratives**
   - ✅ Now: Strict 17-19 line guideline in analytic-story-builder skill

5. **Failed atomic tests and gave up**
   - ✅ Now: Pragmatic testing philosophy allows simulation/faking behavior

6. **Created PRs before completing validation steps**
   - ✅ Now: pr-stager has mandatory pre-flight checklist

7. **Assumed Splunk for all validation/export steps**
   - ✅ Now: Pipeline checks `SIEM_PLATFORM` env var and adapts validation, export, and story creation per platform

---

## Workflow Summary (Post-Updates)

### Correct End-to-End Flow:

1. **Parse Threat Intel** (`cti-analyst`)
2. **Check Coverage** (`coverage-analyzer`)
3. **🆕 Search MCP for existing content** (Phase 2.5)
4. **Create Detections** (`detection-engineer` - outputs format per `SIEM_PLATFORM`)
5. **Validate Detection** (per platform: `contentctl validate` for Splunk, `sigma convert` for Sigma, `detection-rules validate-rule` for Elastic, `az monitor log-analytics query` for KQL)
6. **🆕 Run Atomic Tests** (pragmatic simulation OK!)
7. **Validate in SIEM** (`siem-validator` for any platform, or `splunk-validator` for Splunk-specific)
8. **🆕 Export Attack Data** (`data-dumper` - automatic, supports Splunk/Sentinel/Elastic export)
9. **🆕 Update GitHub URLs** (qa-reviewer checks)
10. **🆕 Verify Story/Grouping** (Splunk: 17-19 line story; Sentinel/Elastic: rule groups)
11. **🆕 Pre-Flight Checklist** (pr-stager - platform-aware)
12. **Create DRAFT PRs** (both repos)

---

## Files Updated

### Agents:
- ✅ `.cursor/agents/orchestrator.md` - Added Phase 2.5 MCP search, pragmatic testing
- ✅ `.cursor/agents/atomic-executor.md` - Added pragmatic testing philosophy
- ✅ `.cursor/agents/detection-engineer.md` - Mandatory MCP search step
- ✅ `.cursor/agents/qa-reviewer.md` - Attack data validation, story length check
- ✅ `.cursor/agents/pr-stager.md` - Pre-flight checklist
- ✅ `.cursor/agents/data-dumper.md` - Automatic export, path structure (already done)
- ✅ `.cursor/agents/splunk-validator.md` - Calls data-dumper (already done)

### Skills:
- ✅ `.claude/skills/atomic-red-team-testing/SKILL.md` - Pragmatic testing philosophy
- ✅ `.claude/skills/analytic-story-builder/SKILL.md` - Concise format (already done)
- ✅ `.claude/skills/detection-yaml-engineer/SKILL.md` - Pragmatic design, GitHub URL structure

---

## Next Time We Run a "Full Workflow"

**These mistakes should NEVER happen again:**
- ❌ Forgetting to export attack data
- ❌ Creating duplicate detections without MCP search
- ❌ Writing book-length analytic stories
- ❌ GitHub URLs pointing to wrong attack_data paths
- ❌ Giving up on atomic tests instead of simulating behavior
- ❌ Creating PRs before completing validation

**The agents will enforce these checks automatically!**
