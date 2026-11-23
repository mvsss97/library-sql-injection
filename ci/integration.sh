#!/usr/bin/env bash
# Build the original lab, run smoke checks, and solve all four checker tasks.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

for tool in docker curl python3 sha1sum php; do
  command -v "$tool" >/dev/null 2>&1 || ci_fail "required tool is unavailable: $tool"
done
docker compose version >/dev/null

CI_WORK_DIR="$(mktemp -d)"
export CI_WORK_DIR
export DEFENSE_DIR="$CI_WORK_DIR/defense"
CHECKER="$CI_WORK_DIR/sqllab"
export CHECKER

cleanup() {
  compose down --volumes --remove-orphans >/dev/null 2>&1 || true
  rm -rf -- "$CI_WORK_DIR"
}
trap cleanup EXIT

cp -R -- "$LABSETUP_DIR/image_www/Code/defense" "$DEFENSE_DIR"
cat >"$CI_WORK_DIR/flags.json" <<'JSON'
{
  "flag_task1": "CiSqlFlagOne123",
  "flag_task2": "CiSqlFlagTwo456",
  "flag_task3": "CiSqlFlagTre789",
  "flag_task4": "CiSqlFlagFor012"
}
JSON

sudo python3 "$REPO_ROOT/provisioning/roles/sql-injection-lab/files/build_checker.py" \
  --flags-file "$CI_WORK_DIR/flags.json" \
  --source "$REPO_ROOT/provisioning/roles/sql-injection-lab/files/sqllab.c" \
  --output "$CHECKER" \
  --owner root \
  --group root \
  --defense-source "$DEFENSE_DIR/unsafe.php"

compose build
compose up --detach
bash "$REPO_ROOT/ci/wait_ready.sh"
bash "$REPO_ROOT/ci/smoke.sh"
bash "$REPO_ROOT/ci/solve_checks.sh"

ci_ok "Compose application and all four checker paths passed"
