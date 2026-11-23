#!/usr/bin/env bash
# Contract tests for the per-sandbox SQL injection checker.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
BUILD_SCRIPT="$REPO_ROOT/provisioning/roles/sql-injection-lab/files/build_checker.py"
CHECKER_SOURCE="$REPO_ROOT/provisioning/roles/sql-injection-lab/files/sqllab.c"

fail() {
  echo "  [FAIL] $*" >&2
  exit 1
}

ok() {
  echo "  [OK]   $*"
}

[[ -f "$BUILD_SCRIPT" ]] || fail "build_checker.py is missing"
[[ -f "$CHECKER_SOURCE" ]] || fail "sqllab.c is missing"

for tool in python3 gcc strings sha256sum stat; do
  command -v "$tool" >/dev/null 2>&1 || fail "required tool is unavailable: $tool"
done

TEST_DIR="$(mktemp -d)"
trap 'rm -rf -- "$TEST_DIR"' EXIT

FLAGS_FILE="$TEST_DIR/flags.json"
CHECKER="$TEST_DIR/sqllab"
cat >"$FLAGS_FILE" <<'JSON'
{
  "flag_task1": "CiSqlFlagOne123",
  "flag_task2": "CiSqlFlagTwo456",
  "flag_task3": "CiSqlFlagTre789",
  "flag_task4": "CiSqlFlagFor012"
}
JSON

sudo python3 "$BUILD_SCRIPT" \
  --flags-file "$FLAGS_FILE" \
  --source "$CHECKER_SOURCE" \
  --output "$CHECKER" \
  --owner root \
  --group root

[[ -x "$CHECKER" ]] || fail "checker is not executable"
[[ "$(stat -c '%a' "$CHECKER")" == "4711" ]] || fail "checker mode is not 4711"
[[ "$(stat -c '%U:%G' "$CHECKER")" == "root:root" ]] || fail "checker is not root-owned"
ok "checker uses secure-exec and is unreadable by students"

while IFS= read -r flag; do
  [[ -n "$flag" ]] || continue
  if sudo grep -aFq -- "$flag" "$CHECKER" || sudo strings "$CHECKER" | grep -Fq -- "$flag"; then
    fail "a plaintext flag is present in the checker"
  fi
done < <(python3 -c 'import json,sys; print("\n".join(json.load(open(sys.argv[1])).values()))' "$FLAGS_FILE")
ok "plaintext flags are absent from the checker"

if [[ "$(id -u)" -ne 0 ]] && "$CHECKER" --selftest >"$TEST_DIR/nonroot.out" 2>&1; then
  fail "--selftest succeeded for a non-root user"
fi
ok "--selftest is restricted to root"

if command -v sudo >/dev/null 2>&1; then
  sudo "$CHECKER" --selftest >"$TEST_DIR/hashes.out"
  python3 - "$FLAGS_FILE" "$TEST_DIR/hashes.out" <<'PY'
import hashlib
import json
import sys

with open(sys.argv[1], encoding="utf-8") as stream:
    flags = json.load(stream)
with open(sys.argv[2], encoding="ascii") as stream:
    actual = [line.strip() for line in stream if line.strip()]
expected = [hashlib.sha256(flags[f"flag_task{number}"].encode()).hexdigest() for number in range(1, 5)]
if actual != expected:
    raise SystemExit(f"self-test hashes differ: expected {expected}, got {actual}")
PY
  ok "root self-test returns the four expected SHA-256 hashes"
else
  echo "  [SKIP] sudo unavailable; root self-test will run in GitHub Actions"
fi

if printf '1\n' | "$CHECKER" check 99 >"$TEST_DIR/invalid.out" 2>&1; then
  fail "an unknown check number was accepted"
fi
if grep -Fq 'CiSqlFlag' "$TEST_DIR/invalid.out"; then
  fail "an invalid invocation disclosed a flag"
fi
ok "invalid invocations fail closed without disclosing flags"
