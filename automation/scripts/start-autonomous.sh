#!/bin/bash
#
# Start Autonomous Detection Engineering Platform
#
# This script starts all components of the autonomous system:
# - Feed collectors
# - Job queue processor
# - Cron scheduler
# - Approval monitor

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   Autonomous Detection Engineering Platform v3.0${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""

# Check environment variables
echo -e "${YELLOW}[1/5] Checking environment...${NC}"

if [ -z "$DETECTIONS_DB_PATH" ]; then
  echo -e "${RED}Error: DETECTIONS_DB_PATH not set${NC}"
  exit 1
fi

if [ ! -f "$DETECTIONS_DB_PATH" ]; then
  echo -e "${RED}Error: Database not found at $DETECTIONS_DB_PATH${NC}"
  exit 1
fi

echo -e "${GREEN}✓ Database found: $DETECTIONS_DB_PATH${NC}"

if [ -z "$ATTACK_RANGE_PATH" ]; then
  echo -e "${YELLOW}Warning: ATTACK_RANGE_PATH not set (atomic validation disabled)${NC}"
fi

echo ""

# Check subagents
echo -e "${YELLOW}[2/5] Verifying Cursor subagents...${NC}"

AGENTS_DIR=".cursor/agents"
REQUIRED_AGENTS=("orchestrator.md" "cti-analyst.md" "detection-engineer.md" "verifier.md" "atomic-executor.md" "splunk-validator.md" "data-dumper.md" "pr-stager.md")

for agent in "${REQUIRED_AGENTS[@]}"; do
  if [ ! -f "$AGENTS_DIR/$agent" ]; then
    echo -e "${RED}Error: Missing subagent: $agent${NC}"
    exit 1
  fi
done

echo -e "${GREEN}✓ All ${#REQUIRED_AGENTS[@]} subagents present${NC}"
echo ""

# Start feed collector
echo -e "${YELLOW}[3/5] Starting feed collector...${NC}"

node automation/collectors/cisa-rss-collector.ts continuous > logs/feed-collector.log 2>&1 &
FEED_PID=$!
echo $FEED_PID > logs/feed-collector.pid

echo -e "${GREEN}✓ Feed collector started (PID: $FEED_PID)${NC}"
echo ""

# Start cron scheduler
echo -e "${YELLOW}[4/5] Starting cron scheduler...${NC}"

node automation/runners/cron-scheduler.ts start > logs/cron-scheduler.log 2>&1 &
CRON_PID=$!
echo $CRON_PID > logs/cron-scheduler.pid

echo -e "${GREEN}✓ Cron scheduler started (PID: $CRON_PID)${NC}"
echo ""

# Start autonomous loop
echo -e "${YELLOW}[5/5] Starting autonomous job processor...${NC}"

node automation/runners/autonomous-loop.ts > logs/autonomous-loop.log 2>&1 &
LOOP_PID=$!
echo $LOOP_PID > logs/autonomous-loop.pid

echo -e "${GREEN}✓ Autonomous loop started (PID: $LOOP_PID)${NC}"
echo ""

# Summary
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo -e "${GREEN}   System Started Successfully${NC}"
echo -e "${GREEN}═══════════════════════════════════════════════════════════════${NC}"
echo ""
echo "Process IDs:"
echo "  Feed Collector:  $FEED_PID"
echo "  Cron Scheduler:  $CRON_PID"
echo "  Autonomous Loop: $LOOP_PID"
echo ""
echo "Logs:"
echo "  tail -f logs/feed-collector.log"
echo "  tail -f logs/autonomous-loop.log"
echo "  tail -f logs/cron-scheduler.log"
echo ""
echo "To stop:"
echo "  ./automation/scripts/stop-autonomous.sh"
echo ""
echo -e "${YELLOW}Note: PRs are staged as DRAFT. Human review required before merge.${NC}"
echo ""
