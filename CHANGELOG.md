# Changelog

All notable changes to the Security Detections MCP project.

## [3.0.0] - 2026-01-30

### 🚀 Major Release: Autonomous Detection Platform

This release transforms the MCP from a query tool into a fully autonomous detection engineering platform. **Version 3.0 includes all features from 2.0/2.1 plus the new autonomous pipeline.**

---

### NEW: Autonomous Pipeline (3.0)

- **LangGraph Pipeline** (`agents/`)
  - `cti-analyst` node - Extract TTPs from threat intel using Claude
  - `coverage-analyzer` node - Check gaps against existing detections
  - `detection-engineer` node - Generate Splunk detection YAMLs
  - `atomic-executor` node - Run Atomic Red Team tests via Attack Range
  - `splunk-validator` node - Validate detections fire using Splunk MCP
  - `data-dumper` node - Export attack data for attack_data repo
  - `pr-stager` node - Create DRAFT PRs to both repos

- **CLI Interface**
  - `npm run orchestrate` - Full pipeline execution
  - `npm run analyze` - Coverage analysis only
  - `npm run validate` - Detection validation only

- **MCP Integration**
  - Uses `splunk-mcp` for detection validation (`run_detection`, `export_dump`)
  - Uses `security-detections` MCP for coverage analysis
  - Uses `mitre-attack` MCP for technique enrichment

- **Human-in-the-Loop**
  - Approval required before PR staging
  - All PRs created as DRAFT (never auto-merge)
  - Cross-referenced PRs between repos

- **Cursor Subagents** (in `security_content/.cursor/agents/`)
  - Interactive versions of each pipeline stage
  - Context-aware IDE integration

- **Documentation**
  - `docs/AUTONOMOUS.md` - Full platform documentation
  - Updated README with 3.0 features
  - Architecture diagrams

---

### INCLUDED: Detection Engineering Intelligence (from 2.0)

- **Pattern Extraction Pipeline** (10,235+ patterns)
  - SPL pattern extraction (macros, data models, field usage, aggregations)
  - Sigma field extraction (common fields, condition patterns)
  - KQL function extraction (Sentinel fields, operators)
  - Elastic ECS field extraction (EQL patterns)

- **Field Reference System**
  - Fields organized by Splunk CIM data model (14 data models)
  - 249+ fields indexed with usage examples
  - Most-used fields ranked by frequency

- **Macro Reference**
  - 127 Splunk macros tracked
  - Essential macros documented (`security_content_summariesonly`, `drop_dm_object_name`, etc.)
  - Usage patterns and best practices

- **Template Generation**
  - `suggest_detection_template` - Generate complete detection YAML
  - `generate_rba_structure` - Create RBA configurations with proper scoring
  - Patterns learned from existing detections

- **Learning from Feedback**
  - `learn_from_feedback` - Store user corrections
  - Continuous improvement of generated templates
  - Tribal knowledge capture

---

### INCLUDED: Knowledge Graph & Tribal Knowledge (from 2.0)

- **Entity Management**
  - 7 entity types: `threat_actor`, `technique`, `detection`, `campaign`, `tool`, `vulnerability`, `data_source`
  - `create_entity`, `delete_entity`, `open_entity` tools

- **Relations with Reasoning**
  - 9 relation types: `uses`, `targets`, `detects`, `covers`, `mitigates`, `exploits`, `attributed_to`, `depends_on`, `related_to`
  - `create_relation` with required reasoning field - captures WHY connections exist
  - Confidence scoring (0.0-1.0)

- **Observations**
  - `add_observation`, `delete_observation` - capture facts about entities
  - Source tracking for provenance

- **Decision Logging**
  - `log_decision` - record analytical decisions with context and reasoning
  - 7 decision types: `gap_identified`, `detection_recommended`, `coverage_mapped`, `priority_assigned`, `false_positive_tuning`, `threat_assessment`, `data_source_selected`
  - Session grouping for related decisions

- **Learnings Storage**
  - `add_learning`, `get_learnings` - store and retrieve reusable patterns
  - 7 learning types: `detection_pattern`, `gap_pattern`, `user_preference`, `false_positive_pattern`, `threat_pattern`, `correlation_insight`, `data_quality_insight`
  - Usage tracking (`times_applied` counter)

- **Knowledge Search**
  - `search_knowledge` - FTS5 full-text search across all knowledge types
  - `read_graph` - read entire knowledge graph or filtered subgraph
  - `get_relevant_decisions` - find past decisions for current context

---

### INCLUDED: 69+ Tools (from 2.0)

- **Detection Search & Retrieval** (8 tools)
  - `search`, `get_by_id`, `list_all`, `list_by_source`, `list_by_mitre`, `list_by_severity`, `get_raw_yaml`, `get_stats`

- **Story Tools** (4 tools)
  - `search_stories`, `get_story`, `list_stories`, `list_stories_by_category`

- **Classification Filters** (11 tools)
  - `list_by_mitre_tactic`, `list_by_cve`, `list_by_process_name`, `list_by_data_source`, `list_by_logsource`, `list_by_detection_type`, `list_by_analytic_story`, `list_by_kql_category`, `list_by_kql_tag`, `list_by_kql_datasource`, `list_by_name_pattern`

- **Coverage & Analysis** (7 tools)
  - `analyze_coverage`, `identify_gaps`, `suggest_detections`, `get_technique_ids`, `get_coverage_summary`, `get_top_gaps`, `get_technique_count`

- **Engineering Intelligence** (8 tools)
  - `get_query_patterns`, `get_field_reference`, `get_macro_reference`, `find_similar_detections`, `suggest_detection_template`, `generate_rba_structure`, `extract_patterns`, `learn_from_feedback`

- **Knowledge Graph** (12 tools)
  - `create_entity`, `create_relation`, `add_observation`, `delete_entity`, `delete_observation`, `search_knowledge`, `read_graph`, `open_entity`, `log_decision`, `add_learning`, `get_relevant_decisions`, `get_learnings`

- **Dynamic Table Tools** (6 tools)
  - `create_table`, `insert_row`, `query_table`, `list_tables`, `drop_table`, `describe_table`

- **Cache & Templates** (8 tools)
  - `save_query`, `get_saved_query`, `list_saved_queries`, `save_template`, `run_template`, `list_templates`, `get_template`, `delete_template`

- **Autonomous Analysis** (3 tools)
  - `auto_analyze_coverage`, `auto_gap_report`, `auto_compare_sources`

- **Comparison Tools** (4 tools)
  - `compare_sources`, `count_by_source`, `get_detection_list`, `smart_compare`

---

### INCLUDED: Core Architecture (from 2.0)

- **Multi-Source Indexing**
  - Sigma rules (YAML)
  - Splunk ESCU detections (YAML)
  - Elastic rules (TOML)
  - KQL queries (Markdown/KQL)

- **SQLite with FTS5**
  - Sub-millisecond full-text search
  - 7,000+ detections indexed
  - Strategic B-tree indexes

- **Database Schema**
  - `detections` table with normalized fields
  - `stories` table for analytic stories
  - `detection_patterns` table for extracted patterns
  - `field_reference` table for data model fields
  - `style_conventions` table for learned conventions
  - Knowledge graph tables: `kg_entities`, `kg_relations`, `kg_observations`, `kg_decisions`, `kg_learnings`

- **MCP Prompts** (11 expert workflows)
- **MCP Resources** (coverage stats, gaps)
- **Argument Completions**
- **Structured Errors**

---

### Changed (3.0)

- Upgraded to LangGraph v1.1.2 (Annotation-based state)
- Upgraded to @langchain/anthropic v1.3.12
- Upgraded to @langchain/core v1.1.17
- Node.js requirement bumped to 20+

### Technical Details (3.0)

- State management via LangGraph Annotations
- TypeScript strict mode throughout
- Proper MCP protocol structure for future wiring
- Attack Range integration follows atomic-red-team-testing skill exactly

---

## [2.1.0] - 2025-12-XX (Merged into 3.0)

### Added
- Additional knowledge graph tools
- Enhanced pattern extraction
- Improved template generation

## [2.0.0] - 2025-11-XX (Merged into 3.0)

### Added
- Detection Engineering Intelligence system
- Knowledge Graph with tribal knowledge capture
- 69+ tools across 10 categories
- Pattern extraction from 10,235+ detections
- Dynamic table storage
- Cache & template system
- MCP Prompts (11 expert workflows)
- MCP Resources (coverage stats, gaps)
- Argument completions
- Structured errors
- Interactive tools (prioritize_gaps, plan_detection_sprint)

## [1.4.1] - 2025-XX-XX

### Added
- KQL support (Bert-JanP, jkerai1 repos)
- KQL-specific filters
- Process name search
- Data source filtering

## [1.0.0] - 2024-XX-XX

### Added
- Initial release
- Sigma, Splunk ESCU, Elastic rule indexing
- MITRE ATT&CK mapping
- Full-text search
- Analytic stories
