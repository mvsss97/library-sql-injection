#!/usr/bin/env bash
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
LABSETUP_DIR="${LABSETUP_DIR:-$REPO_ROOT/provisioning/roles/sql-injection-lab/files/Labsetup}"
COMPOSE_FILE="${COMPOSE_FILE:-$LABSETUP_DIR/docker-compose.yml}"
COMPOSE_PROJECT_NAME="${COMPOSE_PROJECT_NAME:-seed-sqli-ci}"

compose() {
  docker compose --project-name "$COMPOSE_PROJECT_NAME" --file "$COMPOSE_FILE" "$@"
}

web_get() {
  curl --fail --silent --show-error \
    --header 'Host: www.seed-server.com' \
    "http://127.0.0.1$1"
}

ci_ok() {
  echo "  [OK]   $*"
}

ci_fail() {
  echo "  [FAIL] $*" >&2
  return 1
}
