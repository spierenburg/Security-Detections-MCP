#!/usr/bin/env bash
# Long-running refresher loop. Runs refresh-rules.sh, writes marker, sleeps, repeats.
set -u

INTERVAL="${REFRESH_INTERVAL_SECONDS:-86400}"
JITTER="${REFRESH_JITTER_SECONDS:-600}"
MARKER="${LAST_REFRESH_MARKER:-/rules/.last-refresh}"

random_jitter() {
  # shellcheck disable=SC2003
  echo $(( RANDOM % (JITTER + 1) ))
}

while true; do
  echo "[refresher] starting refresh cycle at $(date -Iseconds)" >&2
  if /usr/local/bin/refresh-rules.sh; then
    date -Iseconds > "$MARKER"
    echo "[refresher] cycle complete; marker written to $MARKER" >&2
  else
    echo "[refresher] ERROR: refresh-rules.sh exited non-zero (no repos succeeded); marker NOT updated" >&2
  fi

  sleep_for=$(( INTERVAL + $(random_jitter) ))
  echo "[refresher] sleeping ${sleep_for}s before next cycle" >&2
  sleep "$sleep_for" &
  wait $!
done
