#!/bin/bash
#
# Stop Autonomous Detection Engineering Platform
#
# Gracefully stops all running components

set -e

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

echo -e "${YELLOW}Stopping Autonomous Detection Platform...${NC}"
echo ""

# Stop feed collector
if [ -f logs/feed-collector.pid ]; then
  FEED_PID=$(cat logs/feed-collector.pid)
  if kill -0 $FEED_PID 2>/dev/null; then
    echo -e "${YELLOW}Stopping feed collector (PID: $FEED_PID)...${NC}"
    kill -SIGTERM $FEED_PID
    sleep 2
    echo -e "${GREEN}✓ Feed collector stopped${NC}"
  else
    echo -e "${YELLOW}Feed collector not running${NC}"
  fi
  rm logs/feed-collector.pid
fi

# Stop cron scheduler
if [ -f logs/cron-scheduler.pid ]; then
  CRON_PID=$(cat logs/cron-scheduler.pid)
  if kill -0 $CRON_PID 2>/dev/null; then
    echo -e "${YELLOW}Stopping cron scheduler (PID: $CRON_PID)...${NC}"
    kill -SIGTERM $CRON_PID
    sleep 2
    echo -e "${GREEN}✓ Cron scheduler stopped${NC}"
  else
    echo -e "${YELLOW}Cron scheduler not running${NC}"
  fi
  rm logs/cron-scheduler.pid
fi

# Stop autonomous loop
if [ -f logs/autonomous-loop.pid ]; then
  LOOP_PID=$(cat logs/autonomous-loop.pid)
  if kill -0 $LOOP_PID 2>/dev/null; then
    echo -e "${YELLOW}Stopping autonomous loop (PID: $LOOP_PID)...${NC}"
    kill -SIGTERM $LOOP_PID
    sleep 2
    echo -e "${GREEN}✓ Autonomous loop stopped${NC}"
  else
    echo -e "${YELLOW}Autonomous loop not running${NC}"
  fi
  rm logs/autonomous-loop.pid
fi

echo ""
echo -e "${GREEN}✓ All services stopped${NC}"
echo ""
