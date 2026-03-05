# Autonomous Detection Platform v3.0

The Autonomous Detection Platform transforms the Security Detections MCP from a query tool into a complete **Detection Engineering Team in a Box**.

## Table of Contents

- [Overview](#overview)
- [Architecture](#architecture)
- [Pipeline Stages](#pipeline-stages)
- [Getting Started](#getting-started)
- [Configuration](#configuration)
- [MCP Integration](#mcp-integration)
- [Human-in-the-Loop](#human-in-the-loop)
- [Cursor Subagents](#cursor-subagents)
- [Troubleshooting](#troubleshooting)

## Overview

Feed the platform threat intelligence (CISA alerts, threat reports, specific techniques), and it automatically:

1. Extracts MITRE ATT&CK techniques with proper sub-technique specificity
2. Checks existing detection coverage using the security-detections MCP
3. Prioritizes gaps based on data source availability in your lab environment
4. Generates detection rules in your SIEM's native format (SPL, KQL, EQL, or Sigma)
5. Executes Atomic Red Team tests against your lab targets
6. Validates detections fire by querying your SIEM
7. Exports attack data (format depends on SIEM)
8. Stages DRAFT PRs to your detection repo (never auto-commits)

> **Multi-SIEM Support**: Set `SIEM_PLATFORM` in your `.env` to `splunk`, `sentinel`, `elastic`, or `sigma`. The pipeline adapts its output format, validation method, and export format accordingly. See [E2E Testing Guide](./E2E-TESTING-GUIDE.md) for full setup instructions per SIEM.

## Architecture

### Why Two Systems?

| LangGraph Pipeline | Cursor Subagents |
|-------------------|------------------|
| Core autonomous workflow | Interactive IDE assistance |
| Portable - runs anywhere | Cursor-specific |
| Testable & CI/CD ready | Context-aware |
| Scriptable via CLI | Manual invocation |

The LangGraph pipeline is the "brain" that can run headless, while Cursor Subagents provide specialized IDE assistance.

### Technology Stack

- **LangGraph v1.x** - State machine orchestration with typed annotations
- **@langchain/anthropic** - Claude for CTI analysis and detection generation (swappable -- see [MODELS.md](./MODELS.md))
- **Lab environment** - Attack Range (Splunk), Azure VMs (Sentinel), Docker (Elastic), or any VM with Sysmon
- **SIEM MCP** - Splunk MCP for validation/export (Splunk), Azure CLI (Sentinel), Elasticsearch API (Elastic)
- **GitHub CLI (`gh`)** - DRAFT PR creation

## Pipeline Stages

### 1. CTI Analyst Node

Extracts MITRE ATT&CK techniques from input:

```typescript
// Input types supported
type InputType = 'threat_report' | 'technique' | 'cisa_alert' | 'manual';
```

Key behaviors:
- Uses sub-techniques when available (T1003.001 not T1003)
- Maps to the technique being DETECTED, not the threat actor's goal
- Focuses on behaviors, not IOCs
- Assigns confidence scores (0-1)

### 2. Coverage Analyzer Node

Queries the security-detections MCP to find gaps:

```typescript
// Gap priority levels
type Priority = 'high' | 'medium' | 'low';

// high: No existing coverage
// medium: Only 1 detection for high-confidence technique
// low: Sub-technique coverage improvement
```

Also checks data source availability in Attack Range:
- Sysmon
- Windows Event Log Security 4688
- PowerShell logs
- Zeek (network)

### 3. Detection Engineer Node

Generates detection rules in your SIEM's native format using Claude. The output format depends on `SIEM_PLATFORM`:

| SIEM_PLATFORM | Output Format | Key Conventions |
|---------------|--------------|-----------------|
| `splunk` | SPL YAML | `tstats` with CIM data models, standard macros, RBA risk scoring |
| `sentinel` | KQL analytics rules | `DeviceProcessEvents`, `SigninLogs`, Sentinel analytics rule format |
| `elastic` | EQL/TOML | ECS field names, Elastic detection rule TOML format |
| `sigma` | Sigma YAML | Standard logsource categories, platform-agnostic detection logic |

Output path: `detections/endpoint/<detection_name>.yml` (or `.kql`, `.toml` depending on format)

### 4. Atomic Executor Node

Runs Atomic Red Team tests against your lab environment. The execution method depends on your setup:

**With Attack Range (Splunk):**
```bash
python attack_range.py simulate -e aws -te T1003.001 -t ar-win-ar-youruser
```

**With Azure VMs (Sentinel):**
```bash
az vm run-command invoke --resource-group mylab-rg --name mywin-vm \
  --command-id RunPowerShellScript \
  --scripts "Invoke-AtomicTest T1003.001 -Confirm:\$false"
```

**With any VM (Elastic, Sigma, manual):**
```powershell
# SSH/RDP to target, then:
Invoke-AtomicTest T1003.001
```

Requirements:
- A lab target with Invoke-AtomicRedTeam installed
- For Attack Range: Poetry venv activated, OBJC_DISABLE_INITIALIZE_FORK_SAFETY=YES (macOS)
- For Azure: `az` CLI authenticated
- For manual: SSH/RDP access to target

### 5. SIEM Validator Node

Validates that detections fire against your SIEM. The validation method depends on `SIEM_PLATFORM`:

**Splunk** (via Splunk MCP):
```typescript
await client.callTool({
  server: 'splunk-mcp',
  tool: 'run_detection',
  arguments: { detection_path: '/path/to/detection.yml', auto_prefix: true },
});
```

**Sentinel** (via Azure CLI):
```bash
az monitor log-analytics query --workspace $WORKSPACE \
  --analytics-query "$(cat detection.kql)" --timespan PT1H
```

**Elastic** (via Elasticsearch API):
```bash
curl -XGET "$ELASTICSEARCH_URL/.ds-logs-*/_search" \
  -H 'Content-Type: application/json' -d @query.json
```

**Sigma** (convert then query your SIEM):
```bash
sigma convert -t splunk -p sysmon rule.yml  # convert first
# Then run the converted query against your SIEM
```

Detection status: `draft` → `validated` or `failed`

### 6. Data Dumper Node

Exports attack data from your SIEM for reproducibility:

**Splunk:**
```typescript
await client.callTool({
  server: 'splunk-mcp',
  tool: 'export_dump',
  arguments: {
    search: 'search index=win sourcetype="XmlWinEventLog:..."',
    output_path: '/path/to/output.jsonl',
    earliest: '-2h',
    output_format: 'jsonl',
  },
});
```

**Sentinel:** `az monitor log-analytics query --output json > output.json`

**Elastic:** `curl -XGET "$ELASTICSEARCH_URL/.../_search?scroll=5m" > output.json`

### 7. PR Stager Node

Creates DRAFT PRs using GitHub CLI:

```bash
# security_content PR
gh pr create --draft --title "[Autonomous] Add detections for T1003.001" --body "..."

# attack_data PR (with cross-reference)
gh pr create --draft --title "[Autonomous] Add attack data for T1003.001" --body "..."
```

**CRITICAL**: Always DRAFT, never auto-merge.

## Getting Started

### Prerequisites

**Required (all SIEMs):**
1. **Node.js 20+**
2. **GitHub CLI** - Authenticated (`gh auth login`)
3. **LLM API key** - `ANTHROPIC_API_KEY` for Claude (or see [MODELS.md](./MODELS.md) for alternatives)

**Per-SIEM requirements:**

| SIEM_PLATFORM | Lab Environment | Validation Tool | Additional |
|---------------|----------------|-----------------|------------|
| `splunk` | Attack Range (or any Splunk instance) | Splunk MCP + `contentctl` | `SECURITY_CONTENT_PATH` |
| `sentinel` | Azure VM + Sentinel workspace | Azure CLI (`az`) | Azure subscription |
| `elastic` | Elastic Stack (Docker or cloud) | Elasticsearch API | `ELASTICSEARCH_URL` |
| `sigma` | Any SIEM (convert at validation time) | pySigma | Target backend plugin |

### Installation

```bash
cd agents
npm install --registry https://registry.npmjs.org/
npm run build
```

### Running the Pipeline

```bash
# From a CISA alert
npm run orchestrate -- --type cisa_alert --url https://www.cisa.gov/...

# From a threat report file
npm run orchestrate -- --type threat_report --file ./storm-0501-report.md

# From a specific technique
npm run orchestrate -- --type technique --input "T1566.004 Spearphishing Voice"

# Manual input
npm run orchestrate -- --type manual --input "We observed PowerShell encoded commands..."
```

### CLI Options

```bash
npm run orchestrate -- --help

Options:
  -t, --type <type>      Input type: threat_report, technique, cisa_alert, manual
  -i, --input <text>     Direct input text
  -c, --content <text>   Direct input text (alias for --input)
  -u, --url <url>        URL to fetch (for cisa_alert/threat_report)
  -f, --file <path>      File to read (for threat_report)
  --no-approval          Skip approval prompt (use with caution)
```

## Configuration

### Environment Variables

See `agents/.env.example` for the complete list with comments. Key variables:

| Variable | Description | Required | SIEM |
|----------|-------------|----------|------|
| `SIEM_PLATFORM` | Target SIEM: `splunk`, `sentinel`, `elastic`, `sigma` | Yes | All |
| `ANTHROPIC_API_KEY` | Claude API key (or `OPENAI_API_KEY`, etc.) | Yes | All |
| `SECURITY_CONTENT_PATH` | Path to your detection repository | Yes | All |
| `SPLUNK_MCP_ENABLED` | Enable direct Splunk MCP calls | No | Splunk |
| `ATTACK_RANGE_PATH` | Path to Attack Range | No | Splunk |
| `AZURE_WORKSPACE_NAME` | Azure Log Analytics workspace | No | Sentinel |
| `ELASTICSEARCH_URL` | Elasticsearch endpoint | No | Elastic |
| `SIGMA_TARGET_BACKEND` | Sigma conversion target | No | Sigma |

### Lab Configuration by SIEM

**Splunk + Attack Range:**
```
~/attack_range/
├── attack_range.py
├── .venv/          # Poetry virtualenv
└── ...
```

**Sentinel + Azure:**
```bash
# Ensure Azure CLI is authenticated and workspace exists
az login
az monitor log-analytics workspace show --resource-group mylab-rg --workspace-name detection-lab
```

**Elastic + Docker:**
```bash
# Start Elastic Stack
docker compose up -d  # with elastic's official docker-compose
# Verify: curl http://localhost:9200
```

**No lab (Sigma / rule authoring only):**
The pipeline can run in `DRY_RUN=true` mode, skipping atomic execution and live validation. Useful for generating and validating Sigma rules without a lab.

## MCP Integration

### security-detections MCP

The agents use direct database functions (not MCP tools) for efficiency:
- `searchDetections` - Full-text search across all detections
- `listByMitre` - Check existing coverage for a technique
- `analyzeCoverage` - Get coverage stats by tactic
- `identifyGaps` - Find gaps for threat profiles (ransomware, apt, etc.)
- `suggestDetections` - Get detection recommendations for a technique
- `getStats` - Database statistics

These functions are also available as MCP tools:
- `auto_analyze_coverage` - Automated coverage analysis
- `auto_gap_report` - Comprehensive gap reports
- `auto_compare_sources` - Cross-source comparison

### splunk-mcp

Used for validation and export:
- `run_detection` - Execute detection YAML
- `search` - Run arbitrary SPL
- `export_dump` - Export data to file

### mitre-attack MCP

Used for technique enrichment:
- `get_technique` - Get technique details
- `get_group_techniques` - Get APT TTPs

## Human-in-the-Loop

The platform requires human approval at key checkpoints:

1. **PR Staging** - Before creating any PR
2. **Custom Atomics** - Before deploying non-standard tests

### Approval Flow

```
[PR Stager] Awaiting human approval before staging PRs
[PR Stager] Stage 3 detection(s) as DRAFT PRs? (y/N)
```

### Disabling Approval (Use with Caution)

```bash
npm run orchestrate -- --type technique --input "T1003.001" --no-approval
```

## Cursor Subagents

The `security_content/.cursor/agents/` directory contains specialized subagents:

| Agent | Purpose |
|-------|---------|
| `orchestrator` | Main workflow coordinator |
| `cti-analyst` | Threat intel extraction |
| `coverage-analyzer` | Gap analysis |
| `detection-engineer` | SPL writing |
| `atomic-executor` | Atomic test execution |
| `splunk-validator` | Detection validation |
| `data-dumper` | Attack data export |
| `pr-stager` | PR creation |
| `verifier` | Post-completion verification |

Invoke in Cursor:
```
@orchestrator Run the detection pipeline for this CISA alert
@cti-analyst Extract techniques from this threat report
```

## Troubleshooting

### Attack Range Not Running (Splunk only)

```
[Atomic Executor] Attack Range is not running!
```

Solution:
```bash
cd ~/attack_range
poetry shell
python attack_range.py build
```

**Not using Attack Range?** If you have a manual lab, SSH/RDP to your target and run `Invoke-AtomicTest` directly. Set `ATTACK_RANGE_PATH=` (empty) to skip Attack Range integration.

### SIEM Validation Not Connected

**Splunk:**
```
[Splunk Validator] MCP not enabled - returning call structure
```
Solution: Ensure `user-splunk-mcp` is configured in your MCP settings and `SPLUNK_MCP_ENABLED=true`.

**Sentinel:**
```
[Validator] Azure CLI not authenticated
```
Solution: Run `az login` and set `AZURE_WORKSPACE_NAME` in your `.env`.

**Elastic:**
```
[Validator] Cannot connect to Elasticsearch
```
Solution: Verify `ELASTICSEARCH_URL` is correct and the cluster is running (`curl $ELASTICSEARCH_URL`).

### Detection Validation Fails

```
[Validator] ✗ detection_name: No events matched
```

Possible causes (all SIEMs):
1. Atomic test didn't generate expected events
2. Need more ingestion time (wait 2-3 minutes; increase `INGESTION_WAIT_SECONDS`)
3. Detection query needs adjustment for your environment
4. Field names don't match your SIEM's schema (check [DATA_SOURCES_REFERENCE.md](../.claude/skills/DATA_SOURCES_REFERENCE.md))

### TypeScript Build Errors

```bash
# Clean and rebuild
cd agents
rm -rf dist node_modules
npm install --registry https://registry.npmjs.org/
npm run build
```

## API Usage

For programmatic use:

```typescript
import { runDetectionPipeline } from 'detection-agents';

const result = await runDetectionPipeline(
  'cisa_alert',
  'Full CISA alert text here...',
  'https://cisa.gov/...'
);

console.log(`Created ${result.detections.length} detections`);
console.log(`Validated ${result.detections.filter(d => d.status === 'validated').length}`);
console.log(`PRs staged: ${result.prs.filter(p => p.status === 'staged').length}`);
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make changes to `agents/` (LangGraph) or `.cursor/agents/` (Subagents)
4. Run `npm run typecheck && npm run build`
5. Test with a real threat report
6. Submit PR

## License

Apache 2.0
