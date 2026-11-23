#!/usr/bin/env bash
set -euo pipefail

source "$(dirname "${BASH_SOURCE[0]}")/lib.sh"

home="$(web_get /)"
grep -Fq 'Employee Management' <<<"$home" || ci_fail "login page is missing"
ci_ok "login page responds through the expected virtual host"

admin="$(web_get '/unsafe_home.php?username=Admin%27%20%23&Password=x')"
for marker in 'User Details' Alice Boby 99999; do
  grep -Fq "$marker" <<<"$admin" || ci_fail "admin injection response is missing: $marker"
done
ci_ok "the intentionally vulnerable SELECT can expose the admin roster"

database_state="$(compose exec --no-TTY mysql \
  mysql --batch --skip-column-names -uroot -pdees sqllab_users \
  --execute="SELECT CONCAT(Name, ':', EID, ':', Salary, ':', SSN) FROM credential WHERE Name IN ('Alice','Boby') ORDER BY ID;")"
grep -Fq 'Alice:10000:20000:10211002' <<<"$database_state" \
  || ci_fail "Alice baseline row is incorrect"
grep -Fq 'Boby:20000:30000:10213352' <<<"$database_state" \
  || ci_fail "Boby baseline row is incorrect"
ci_ok "database was initialized with the expected baseline"

accounts="$(compose exec --no-TTY mysql \
  mysql --batch --skip-column-names -uroot -pdees mysql \
  --execute="SELECT User FROM user WHERE User IN ('seed','student_ro','defense_ro') ORDER BY User;")"
for account in seed student_ro defense_ro; do
  grep -Fxq "$account" <<<"$accounts" || ci_fail "database account is missing: $account"
done
ci_ok "web, read-only student and read-only defense accounts exist"
