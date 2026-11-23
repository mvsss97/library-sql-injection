#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

for attempt in $(seq 1 90); do
  if [[ "$(web_get /healthz.php 2>/dev/null || true)" == "ok" ]]; then
    ci_ok "Apache/PHP and MySQL are ready"
    exit 0
  fi
  if (( attempt % 15 == 0 )); then
    echo "  [WAIT] services are still starting ($attempt/90)"
  fi
  sleep 2
done

compose ps >&2 || true
compose logs --no-color >&2 || true
ci_fail "services did not become ready within 180 seconds"
