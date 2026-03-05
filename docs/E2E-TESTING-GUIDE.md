# End-to-End Detection Testing Guide

How to set up a full detection validation pipeline -- from threat intel to validated, PR-ready detections -- on your own system.

---

## Architecture Overview

```
Threat Intelligence
       │
       ▼
┌─────────────────┐
│  CTI Analyst     │  Extract MITRE ATT&CK TTPs
│  (LLM node)     │
└────────┬────────┘
         ▼
┌─────────────────┐
│ Coverage Analyzer│  Query security-detections MCP
│ (MCP + LLM)     │  for existing coverage → find gaps
└────────┬────────┘
         ▼
┌─────────────────┐
│ Detection Eng.   │  Generate detection rules
│ (LLM node)      │  (SPL / KQL / Sigma / Elastic)
└────────┬────────┘
         ▼
┌─────────────────┐
│ Atomic Executor  │  Run Atomic Red Team tests
│ (Attack Range)   │  against lab environment
└────────┬────────┘
         ▼
┌─────────────────┐
│ SIEM Validator   │  Query SIEM to confirm
│ (MCP)            │  detection fires
└────────┬────────┘
         ▼
┌─────────────────┐
│ Data Dump + PR   │  Export attack data,
│ (git + gh)       │  stage DRAFT PR
└─────────────────┘
```

Each box is a LangGraph node (in `agents/nodes/`) *and* a Cursor subagent (in `.cursor/agents/`). You can run the full pipeline automatically via the LangGraph CLI, or step through it interactively with Cursor agents.

---

## What You Need to Customize

Before diving into setup, here are the **3-5 key things** you must configure for your environment. Everything else has sensible defaults.

### 1. Pick Your SIEM Platform

Set `SIEM_PLATFORM` in your `.env` file. This controls what detection format the pipeline generates:

| Value | Detection Format | Validation Tool | Lab Environment |
|-------|-----------------|-----------------|-----------------|
| `splunk` | SPL YAML (security_content) | `contentctl validate` | Attack Range (AWS) or any Splunk instance |
| `sentinel` | KQL analytics rules | Azure CLI (`az monitor log-analytics query`) | Azure VMs with Defender/Sentinel |
| `elastic` | EQL/TOML detection rules | Elastic detection-rules CLI or Kibana API | Elastic Stack (Docker or cloud) |
| `sigma` | Sigma YAML (platform-agnostic) | `pySigma` + backend conversion | Any SIEM (convert at deploy time) |

### 2. Set Your Repository Paths

Point to where your detection content lives:

```bash
# Required: where your detections are stored
SECURITY_CONTENT_PATH=/path/to/your/detection-repo

# Optional: attack data repo (Splunk-specific)
ATTACK_DATA_PATH=/path/to/attack_data
```

### 3. Configure Your Lab Environment

You need a target machine that generates telemetry your SIEM can ingest. Choose one:

| Option | Best For | Cost | Setup Time |
|--------|----------|------|------------|
| **Attack Range** (AWS) | Splunk users, full automation | ~$5-15/day | ~30 min |
| **Azure VM** + Sentinel | Microsoft shops | Free tier available | ~1 hour |
| **Docker Elastic Stack** | Elastic users, local testing | Free | ~20 min |
| **Existing VM + Sysmon** | Any SIEM, reuse infrastructure | Free | ~15 min |
| **No lab** (Sigma only) | Rule authoring without live validation | Free | ~5 min |

### 4. Set Your LLM Provider

```bash
# Default: Anthropic Claude
ANTHROPIC_API_KEY=sk-ant-...
LLM_MODEL=claude-sonnet-4-20250514

# Alternative: OpenAI (requires code change in node files)
# OPENAI_API_KEY=sk-...
# LLM_MODEL=gpt-4o
```

See [docs/MODELS.md](./MODELS.md) for full provider setup.

### 5. (Optional) Configure Validation

Each SIEM has its own validation tool. Set `VALIDATION_TOOL` or rely on the defaults:

| SIEM | Validation Tool | Install |
|------|----------------|---------|
| Splunk | `contentctl` | `cd $SECURITY_CONTENT_PATH && source venv/bin/activate` |
| Sentinel | Azure CLI | `az monitor log-analytics query` |
| Elastic | detection-rules CLI | `pip install detection-rules` |
| Sigma | pySigma | `pip install pySigma pySigma-backend-splunk` |

### Quick Config Summary

```bash
# Copy and edit the env file
cp agents/.env.example agents/.env

# The 3 critical settings:
SIEM_PLATFORM=sentinel          # or splunk, elastic, sigma
SECURITY_CONTENT_PATH=./my-detections
ANTHROPIC_API_KEY=sk-ant-...    # or OPENAI_API_KEY
```

---

## How We Built This (The Original Approach)

The pipeline was developed against Splunk's [security_content](https://github.com/splunk/security_content) repository using:

1. **Attack Range** (Splunk's open-source lab) -- spins up a Splunk instance + Windows/Linux targets in AWS with Sysmon, PowerShell logging, and Zeek pre-configured.
2. **Atomic Red Team** -- standard + custom atomics (T9999.XXX series) executed via Attack Range CLI.
3. **contentctl** -- Splunk's validation tool that checks detection YAMLs against a strict schema.
4. **Splunk MCP** -- the `splunk-mcp` MCP server for live SPL queries and data export.
5. **security-detections MCP** -- indexes ~7,200+ detections across Sigma, Splunk ESCU, Elastic, and KQL for coverage analysis.

The workflow: parse threat report → check existing coverage via MCP → write Splunk SPL detections → run atomics on Attack Range → validate in Splunk → export attack data → stage DRAFT PR.

Everything below shows how to replicate this for **your** SIEM.

---

## Option A: Splunk + Attack Range (Original)

### Prerequisites
- AWS account (Attack Range provisions EC2 instances)
- Python 3.10+ with Poetry
- Terraform
- Ansible
- ~$5-15/day in AWS costs while the range is running

### Setup

```bash
# 1. Clone repos
git clone https://github.com/splunk/attack_range.git
git clone https://github.com/splunk/security_content.git
git clone https://github.com/splunk/attack_data.git

# 2. Install Attack Range
cd attack_range
poetry install
poetry shell

# 3. Configure (edit attack_range.yml)
#    - Set your AWS region, key name, IP whitelist
#    - Enable windows_servers, linux_servers as needed

# 4. Build the range (~15-30 min)
python attack_range.py build

# 5. Check status
python attack_range.py show
#    → Splunk URL, Windows target name, Linux target IP
```

### Environment Variables

```bash
export SECURITY_CONTENT_PATH=/path/to/security_content
export ATTACK_DATA_PATH=/path/to/attack_data
export ATTACK_RANGE_PATH=/path/to/attack_range
export ATTACK_RANGE_VENV=/path/to/poetry/venv/bin/activate
export ATTACK_RANGE_DEFAULT_TARGET=ar-win-yourlab-0
export SPLUNK_MCP_ENABLED=true
export ANTHROPIC_API_KEY=sk-ant-...
```

### Running the Pipeline

```bash
cd agents
npm install
npm run orchestrate -- --type threat_report --url https://www.cisa.gov/news-events/alerts/...
```

Or step-by-step with Cursor: open the project, invoke the `orchestrator` agent, and follow its phases.

### Running Atomics

```bash
# Standard Atomic Red Team test
python attack_range.py simulate -e ART -te T1003.001 -t <TARGET_NAME>

# Custom atomic (deploy first, then execute)
ansible-playbook -i '<TARGET_IP>,' deploy_custom_atomics.yml
python attack_range.py simulate -e ART -te T9999.001 -t <TARGET_NAME>

# Wait 2-3 minutes for Splunk ingestion, then validate
```

### Validating Detections

Use the Splunk MCP:
```
splunk-mcp:run_detection(detection_path="detections/endpoint/your_detection.yml")
```

Or run the SPL manually in the Splunk UI / via REST API.

### Cost Management

```bash
# Stop range when not testing (saves money, keeps config)
python attack_range.py stop

# Resume when ready
python attack_range.py resume

# Destroy completely
python attack_range.py destroy
```

---

## Option B: Microsoft Sentinel / KQL

### Prerequisites
- Azure subscription (free tier works for small labs)
- Log Analytics workspace
- Microsoft Sentinel enabled on the workspace
- One or more VMs sending logs (Windows with MDE, or Linux with Azure Monitor Agent)

### Setup

```bash
# 1. Create a Log Analytics workspace
az monitor log-analytics workspace create \
  --resource-group mylab-rg \
  --workspace-name detection-lab \
  --location eastus

# 2. Enable Sentinel on the workspace
az sentinel onboarding-state create \
  --resource-group mylab-rg \
  --workspace-name detection-lab

# 3. Deploy a Windows VM with Defender for Endpoint
#    (or use Azure Arc to onboard an existing machine)
#    Ensure data connectors are enabled:
#    - Microsoft Defender for Endpoint
#    - Windows Security Events via AMA
#    - Sysmon (optional but recommended)

# 4. Verify data flowing
#    In Sentinel > Logs, run:
#    DeviceProcessEvents | take 10
```

### Writing KQL Detections

KQL analytics rules go in your detection repo as `.kql` or `.yaml` files:

```kql
// Detection: Suspicious LSASS Access
// MITRE: T1003.001
DeviceProcessEvents
| where Timestamp > ago(1h)
| where FileName == "procdump.exe" or FileName == "procdump64.exe"
| where ProcessCommandLine has "lsass"
| project Timestamp, DeviceName, AccountName, FileName, ProcessCommandLine
```

To deploy as a Sentinel Analytics Rule:
```bash
# Using Azure CLI
az sentinel alert-rule create \
  --resource-group mylab-rg \
  --workspace-name detection-lab \
  --rule-name "Suspicious LSASS Access" \
  --query "DeviceProcessEvents | where FileName in~ ('procdump.exe','procdump64.exe') | where ProcessCommandLine has 'lsass'"
```

### Running Atomics Against Azure VMs

Install Invoke-AtomicRedTeam on the target VM:
```powershell
# On the Windows VM
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

# Run a test
Invoke-AtomicTest T1003.001
```

Or use Azure Automation / Run Command:
```bash
az vm run-command invoke \
  --resource-group mylab-rg \
  --name mywin-vm \
  --command-id RunPowerShellScript \
  --scripts "Invoke-AtomicTest T1003.001 -Confirm:\$false"
```

### Validating in Sentinel

```kql
// Check if the detection would have fired
DeviceProcessEvents
| where Timestamp > ago(30m)
| where FileName in~ ("procdump.exe", "procdump64.exe")
| where ProcessCommandLine has "lsass"
| count
// count > 0 = detection fires
```

### Adapting the Pipeline

To point the LangGraph pipeline at Sentinel instead of Splunk:

1. **Set environment variables** in `agents/.env`:
   ```bash
   SIEM_PLATFORM=sentinel
   LLM_MODEL=claude-sonnet-4-20250514  # or gpt-4o

   # Sentinel-specific (optional)
   AZURE_SUBSCRIPTION_ID=your-sub-id
   AZURE_RESOURCE_GROUP=mylab-rg
   AZURE_WORKSPACE_NAME=detection-lab

   # Not needed for Sentinel:
   # SPLUNK_MCP_ENABLED=false  (default)
   # ATTACK_RANGE_PATH         (not used)
   # ATTACK_DATA_PATH           (not used)
   ```

2. The `detection-engineer` node generates KQL instead of SPL when `SIEM_PLATFORM=sentinel`.

3. For validation, replace Splunk MCP calls with Azure Log Analytics REST API queries or use the [Azure Monitor MCP](https://github.com/microsoft/azure-mcp) if available.

4. Data export: Use `az monitor log-analytics query` to export matching events.

5. **Validation alternative** (no Azure MCP): Run KQL queries manually in Sentinel > Logs, or use the Azure CLI:
   ```bash
   az monitor log-analytics query \
     --workspace $AZURE_WORKSPACE_NAME \
     --analytics-query "$(cat your_detection.kql)" \
     --timespan PT1H
   ```

### Key KQL Tables

| Table | What It Contains | Equivalent Splunk Source |
|-------|-----------------|------------------------|
| `DeviceProcessEvents` | Process creation | Sysmon EventID 1 |
| `DeviceNetworkEvents` | Network connections | Sysmon EventID 3 |
| `DeviceFileEvents` | File operations | Sysmon EventID 11 |
| `DeviceRegistryEvents` | Registry changes | Sysmon EventID 13 |
| `DeviceLogonEvents` | Authentication | Security 4624/4625 |
| `SigninLogs` | Azure AD sign-ins | Azure AD logs |
| `EmailEvents` | Email activity | O365 logs |

---

## Option C: Elastic Security

### Prerequisites
- Elastic Stack 8.x (Elasticsearch + Kibana)
- Elastic Agent with Fleet (for endpoint telemetry)
- At least one Windows/Linux endpoint enrolled

### Setup

```bash
# 1. Start Elastic Stack (Docker is easiest for a lab)
docker compose up -d  # with elastic's official docker-compose

# 2. Enable Elastic Security in Kibana
#    Navigate to Security > Overview
#    Install the Elastic Defend integration via Fleet

# 3. Enroll an agent on your test VM
#    Fleet > Add agent > copy the enrollment command
#    Run on target: ./elastic-agent install --url=... --enrollment-token=...

# 4. Verify data
#    In Kibana Dev Tools:
GET .ds-logs-endpoint.events.process-*/_search?size=1
```

### Writing Elastic Detections

Elastic uses TOML for detection rules, or you can write EQL/ES|QL:

**EQL (Event Query Language):**
```eql
process where process.name == "procdump.exe" and process.args : "*lsass*"
```

**ES|QL:**
```esql
FROM logs-endpoint.events.process-*
| WHERE process.name == "procdump.exe" AND process.command_line LIKE "*lsass*"
| KEEP @timestamp, host.name, user.name, process.name, process.command_line
```

**Detection rule TOML:**
```toml
[rule]
name = "Suspicious LSASS Access via Procdump"
rule_id = "your-uuid-here"
risk_score = 73
severity = "high"
type = "eql"
query = '''
process where process.name == "procdump.exe" and process.args : "*lsass*"
'''

[rule.threat]
framework = "MITRE ATT&CK"

[[rule.threat.technique]]
id = "T1003"
name = "OS Credential Dumping"

[[rule.threat.technique.subtechnique]]
id = "T1003.001"
name = "LSASS Memory"
```

### Running Atomics

Same as any platform -- install Invoke-AtomicRedTeam on the target endpoint and run tests. Elastic Agent picks up the telemetry automatically.

### Validating

```bash
# Query Elasticsearch directly
curl -XGET "localhost:9200/.ds-logs-endpoint.events.process-*/_search" \
  -H 'Content-Type: application/json' \
  -d '{"query":{"bool":{"must":[{"match":{"process.name":"procdump.exe"}},{"match_phrase":{"process.command_line":"lsass"}}]}}}'
```

Or use Kibana Security > Detections to see if the rule fired.

### Adapting the Pipeline

1. **Set environment variables** in `agents/.env`:
   ```bash
   SIEM_PLATFORM=elastic
   LLM_MODEL=claude-sonnet-4-20250514

   # Elastic-specific (optional)
   ELASTICSEARCH_URL=http://localhost:9200
   KIBANA_URL=http://localhost:5601

   # Not needed for Elastic:
   # SPLUNK_MCP_ENABLED=false  (default)
   # ATTACK_RANGE_PATH         (not used)
   ```

2. Detection engineer outputs EQL or TOML instead of SPL.

3. Validation uses Elasticsearch REST API instead of Splunk MCP:
   ```bash
   # Query Elasticsearch for detection results
   curl -XGET "$ELASTICSEARCH_URL/.ds-logs-endpoint.events.process-*/_search" \
     -H 'Content-Type: application/json' \
     -d @your_query.json
   ```

4. Data export: Use Elasticsearch `_search` API with scroll/PIT.

5. **Validation alternative** (CLI): Use the Elastic detection-rules CLI:
   ```bash
   git clone https://github.com/elastic/detection-rules.git
   cd detection-rules && pip install .
   python -m detection_rules validate-rule path/to/rule.toml
   ```

### Key Elastic Indices

| Index Pattern | What It Contains | Equivalent |
|--------------|-----------------|------------|
| `logs-endpoint.events.process-*` | Process events | Sysmon 1 / CIM Processes |
| `logs-endpoint.events.network-*` | Network events | Sysmon 3 / CIM Network_Traffic |
| `logs-endpoint.events.file-*` | File events | Sysmon 11 / CIM Filesystem |
| `logs-endpoint.events.registry-*` | Registry events | Sysmon 13 |
| `logs-system.auth-*` | Auth events | Security 4624 |

---

## Option D: Sigma (Platform-Agnostic)

### Why Sigma?

Sigma rules are SIEM-agnostic -- write once, convert to any backend. This is the best approach if you support multiple SIEMs or want maximum portability.

### Prerequisites
- Python 3.8+
- pySigma (`pip install pySigma`)
- Backend plugins for your target SIEM

### Setup

```bash
# Install pySigma and backends
pip install pySigma
pip install pySigma-backend-splunk      # for Splunk output
pip install pySigma-backend-microsoft365defender  # for KQL output
pip install pySigma-backend-elasticsearch  # for Elastic output

# Install pipelines (field mapping)
pip install pySigma-pipeline-sysmon
pip install pySigma-pipeline-windows
```

### Writing Sigma Rules

```yaml
title: Suspicious LSASS Access via Procdump
id: your-uuid-here
status: stable
level: high
description: Detects procdump being used to dump LSASS memory.
author: Your Name
date: 2026/02/06
references:
  - https://attack.mitre.org/techniques/T1003/001/
tags:
  - attack.credential_access
  - attack.t1003.001
logsource:
  category: process_creation
  product: windows
detection:
  selection:
    Image|endswith: '\procdump.exe'
    CommandLine|contains: 'lsass'
  condition: selection
falsepositives:
  - Legitimate memory dump for debugging
```

### Converting to Your SIEM

```bash
# To Splunk SPL
sigma convert -t splunk -p sysmon rule.yml

# To Microsoft 365 Defender KQL
sigma convert -t microsoft365defender rule.yml

# To Elasticsearch Lucene query
sigma convert -t elasticsearch rule.yml

# To Elasticsearch EQL
sigma convert -t elasticsearch -f eql rule.yml
```

### Validation Workflow with Sigma

1. Write Sigma rule
2. Convert to your SIEM's query language
3. Run the converted query against your lab
4. If it fires, the rule is valid
5. Commit the Sigma rule (not the converted output)

### Adapting the Pipeline

1. **Set environment variables** in `agents/.env`:
   ```bash
   SIEM_PLATFORM=sigma
   LLM_MODEL=claude-sonnet-4-20250514

   # Sigma-specific: which backend to convert to for validation
   SIGMA_TARGET_BACKEND=splunk  # or microsoft365defender, elasticsearch

   # Not needed for Sigma:
   # SPLUNK_MCP_ENABLED=false  (default)
   # ATTACK_RANGE_PATH         (not used)
   ```

2. Detection engineer outputs Sigma YAML.
3. Validation step converts to your SIEM's format, then queries:
   ```bash
   # Convert and validate in one step
   sigma convert -t splunk -p sysmon rule.yml | \
     splunk search "$(cat -)"
   ```
4. Store the Sigma rule in your repo; conversion happens at deploy time.

5. **Best practice**: Use Sigma as the source of truth and maintain a CI/CD pipeline that converts to your SIEM's native format on merge.

---

## Running Atomic Red Team (All Platforms)

Regardless of SIEM, the atomic testing workflow is the same:

### Install on Windows Target

```powershell
# Install Invoke-AtomicRedTeam
IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing)
Install-AtomicRedTeam -getAtomics

# List available tests for a technique
Invoke-AtomicTest T1003.001 -ShowDetailsBrief

# Run a specific test
Invoke-AtomicTest T1003.001 -TestNumbers 1

# Run all tests for a technique
Invoke-AtomicTest T1003.001
```

### Install on Linux Target

```bash
# Install Invoke-AtomicRedTeam (PowerShell required)
pwsh -c "IEX (IWR 'https://raw.githubusercontent.com/redcanaryco/invoke-atomicredteam/master/install-atomicredteam.ps1' -UseBasicParsing); Install-AtomicRedTeam -getAtomics"

# Or use the bash runner
git clone https://github.com/redcanaryco/atomic-red-team.git
cd atomic-red-team/atomics/T1003.001
bash T1003.001.sh  # if a bash variant exists
```

### Custom Atomics (T9999.XXX)

When standard Atomic Red Team tests don't cover your specific detection behavior:

1. Create a custom atomic YAML following the [Atomic Red Team format](https://github.com/redcanaryco/atomic-red-team/wiki/Contributing)
2. Use the T9999.XXX numbering convention (avoids conflicts with official tests)
3. Deploy via Ansible playbook or direct copy to the target
4. Execute and wait for log ingestion

### Pragmatic Testing

You don't need actual malware. Focus on generating telemetry that matches your detection logic:
- Copy legit binaries to suspicious names (`cmd.exe` -> `svchost.exe`)
- Run with suspicious command-line flags
- Create files in monitored paths
- The goal is validating detection logic, not replicating malware perfectly

---

## Quick Start Checklist

Minimum viable setup for your first e2e detection validation:

1. [ ] **Pick your SIEM** -- Splunk, Sentinel, Elastic, or Sigma
2. [ ] **Set up a lab target** -- One Windows VM with Sysmon (or equivalent logging)
3. [ ] **Install atomics** -- Invoke-AtomicRedTeam on the target
4. [ ] **Configure env vars** -- Copy `agents/.env.example` to `.env` and fill in paths
5. [ ] **Install MCP servers** -- At minimum `security-detections` for coverage analysis
6. [ ] **Run a test** -- Execute `T1003.001` on the target, wait 3 minutes
7. [ ] **Query your SIEM** -- Confirm the events show up
8. [ ] **Write a detection** -- Create a rule that matches the telemetry
9. [ ] **Validate** -- Run the detection query, confirm count > 0
10. [ ] **Export** -- Save the validated data and stage a PR

---

## Comparison Table

| Feature | Splunk + Attack Range | Sentinel | Elastic | Sigma |
|---------|----------------------|----------|---------|-------|
| Cost | ~$5-15/day AWS | Free tier available | Free (self-hosted) | Free |
| Setup time | ~30 min | ~1 hour | ~20 min (Docker) | ~5 min |
| Built-in atomics | Yes (via Attack Range) | Manual install | Manual install | N/A |
| Detection format | SPL YAML | KQL | EQL/TOML | Sigma YAML |
| Validation tool | contentctl | Azure CLI | Detection Engine | pySigma |
| MCP available | splunk-mcp | azure-mcp (community) | Not yet | N/A |
| Best for | Splunk shops, security_content contributors | Microsoft/Azure shops | Elastic shops | Multi-SIEM, portability |

---

## Autonomous Pipeline Configuration

To run the LangGraph pipeline for your SIEM:

```bash
# 1. Set your platform
export SIEM_PLATFORM=sentinel  # or splunk, elastic, sigma

# 2. Set paths
export SECURITY_CONTENT_PATH=./my-detections
export ANTHROPIC_API_KEY=sk-ant-...

# 3. Run
cd agents
npm install
npm run orchestrate -- --type technique --input "T1566.004 Spearphishing Voice"
```

The pipeline adapts its detection output format based on `SIEM_PLATFORM`. The CTI analysis and coverage check steps are platform-agnostic (they use the security-detections MCP which indexes rules from all formats).
