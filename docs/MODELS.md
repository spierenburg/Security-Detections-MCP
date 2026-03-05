# Model Configuration Guide

The detection pipeline and Cursor agents reference model tiers instead of hardcoded model names so you can swap providers without editing every file.

## Model Tiers

| Tier | Used For | Examples |
|------|----------|---------|
| **fast** | High-volume, low-latency tasks (coverage checks, FP scoring, verification) | Claude Haiku, GPT-4o-mini, Gemini Flash |
| **inherit** | Same model as the parent caller (orchestrator, validators) | Whatever Cursor is running |
| **default** | Standard tasks (detection creation, CTI analysis, PR review) | Claude Sonnet, GPT-4o, Gemini Pro |

## Configuring the LangGraph Pipeline

The `agents/` pipeline reads the model from the `LLM_MODEL` environment variable (see `agents/.env.example`):

```bash
# Claude (default)
LLM_MODEL=claude-sonnet-4-20250514

# OpenAI
LLM_MODEL=gpt-4o

# Google
LLM_MODEL=gemini-2.0-flash
```

To use a non-Anthropic provider you'll also need to swap the `ChatAnthropic` import in the node files for the appropriate LangChain chat model class (`ChatOpenAI`, `ChatGoogleGenerativeAI`, etc.) and set the matching API key env var (`OPENAI_API_KEY`, `GOOGLE_API_KEY`).

## Configuring Cursor Agents

Cursor agent files (`.cursor/agents/*.md`) use the `model:` frontmatter field:

```yaml
---
name: cti-analyst
model: fast          # uses your fastest configured model
---
```

```yaml
---
name: orchestrator
model: inherit       # uses whatever model you've selected in Cursor
---
```

Cursor maps these tier names to actual models in **Settings > Models**. Configure your preferred provider there.

## Configuring Claude Code Skills

Claude Code (`.claude/skills/`) doesn't have a model selector -- it uses whatever model you've configured in your Claude Code client. The skills are pure methodology docs so they work identically regardless of the underlying model.

## Provider Quick Setup

### Anthropic (default)
```bash
export ANTHROPIC_API_KEY=sk-ant-...
export LLM_MODEL=claude-sonnet-4-20250514
```

### OpenAI
```bash
export OPENAI_API_KEY=sk-...
export LLM_MODEL=gpt-4o
```
Then in each node file, change:
```typescript
// from
import { ChatAnthropic } from '@langchain/anthropic';
// to
import { ChatOpenAI } from '@langchain/openai';
```

### Azure OpenAI
```bash
export AZURE_OPENAI_API_KEY=...
export AZURE_OPENAI_ENDPOINT=https://your-resource.openai.azure.com/
export LLM_MODEL=gpt-4o
```

### Google Vertex / Gemini
```bash
export GOOGLE_API_KEY=...
export LLM_MODEL=gemini-2.0-flash
```

## MCP Server Models

The MCP servers (`security-detections`, `splunk-mcp`, `mitre-attack`) are model-agnostic -- they provide data, not LLM calls. They work with any provider.
