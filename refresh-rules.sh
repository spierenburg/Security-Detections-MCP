#!/usr/bin/env bash
# Clones or pulls all upstream detection-rule repos.
# Resilient: per-repo failures are logged and counted, do not abort the loop.
# Exits 0 if at least one repo succeeded, 1 if all failed.

set -u -o pipefail

RULES_DIR="${RULES_DIR:-$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/rules}"
mkdir -p "$RULES_DIR"
cd "$RULES_DIR" || { echo "[refresh] FATAL: cannot cd to $RULES_DIR" >&2; exit 1; }

REPOS=(
  "sigma            https://github.com/SigmaHQ/sigma.git"
  "security_content https://github.com/splunk/security_content.git"
  "detection-rules  https://github.com/elastic/detection-rules.git"
  "KQL-Bert-JanP    https://github.com/Bert-JanP/Hunting-Queries-Detection-Rules.git"
  "KQL-jkerai1      https://github.com/jkerai1/KQL-Queries.git"
  "sublime-rules    https://github.com/sublime-security/sublime-rules.git"
  "Query-Hub        https://github.com/ByteRay-Labs/Query-Hub.git"
  "attack-stix-data https://github.com/mitre-attack/attack-stix-data.git"
)

ok=0
fail=0

clone_or_pull() {
  local dir="$1" url="$2"
  if [ -d "$dir/.git" ]; then
    printf '[refresh] pulling %-24s ... ' "$dir" >&2
    if git -C "$dir" pull --ff-only --quiet 2>/dev/null; then
      echo "ok" >&2
      return 0
    fi
    echo "FAIL" >&2
    return 1
  fi
  printf '[refresh] cloning %-24s ... ' "$dir" >&2
  if git clone --depth 1 --quiet "$url" "$dir" 2>/dev/null; then
    echo "ok" >&2
    return 0
  fi
  echo "FAIL" >&2
  return 1
}

for line in "${REPOS[@]}"; do
  # shellcheck disable=SC2086
  set -- $line
  name="$1"
  url="$2"
  if clone_or_pull "$name" "$url"; then
    ok=$((ok + 1))
  else
    fail=$((fail + 1))
  fi
done

echo "[refresh] summary: $ok ok, $fail failed" >&2

if [ "$ok" -eq 0 ]; then
  exit 1
fi

{
  echo "[refresh] rule counts:"
  printf '  sigma           %s\n' "$(find sigma/rules sigma/rules-threat-hunting -type f -name '*.yml' 2>/dev/null | wc -l | tr -d ' ')"
  printf '  splunk ESCU     %s\n' "$(find security_content/detections -type f -name '*.yml' 2>/dev/null | wc -l | tr -d ' ')"
  printf '  elastic         %s\n' "$(find detection-rules/rules -type f -name '*.toml' 2>/dev/null | wc -l | tr -d ' ')"
  printf '  KQL             %s\n' "$(find KQL-Bert-JanP KQL-jkerai1 -type f \( -name '*.kql' -o -name '*.md' \) 2>/dev/null | wc -l | tr -d ' ')"
  printf '  sublime         %s\n' "$(find sublime-rules/detection-rules -type f -name '*.yml' 2>/dev/null | wc -l | tr -d ' ')"
  printf '  CrowdStrike CQL %s\n' "$(find Query-Hub -type f 2>/dev/null | wc -l | tr -d ' ')"
} >&2

exit 0
