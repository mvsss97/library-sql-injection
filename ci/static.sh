#!/usr/bin/env bash
# Fast validation: metadata, PHP, Python, C checker, Compose and Ansible syntax.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$REPO_ROOT"

python3 -m json.tool training.json >/dev/null
python3 - <<'PY'
from pathlib import Path
import yaml

for path in [Path("topology.yml"), Path("variables.yml"), Path("provisioning/requirements.yml")]:
    with path.open(encoding="utf-8") as stream:
        document = yaml.safe_load(stream)
    if document is None:
        raise SystemExit(f"empty YAML document: {path}")
print("  [OK]   JSON and YAML metadata parse successfully")
PY

python3 -m py_compile provisioning/roles/sql-injection-lab/files/build_checker.py
echo "  [OK]   build_checker.py compiles"

while IFS= read -r -d '' php_file; do
  php -l "$php_file" >/dev/null
done < <(find provisioning/roles/sql-injection-lab/files/Labsetup/image_www/Code ci \
  -type f -name '*.php' -print0)
echo "  [OK]   every PHP file passes php -l"

while IFS= read -r shell_file; do
  bash -n "$shell_file"
done < <(find ci -maxdepth 1 -type f -name '*.sh' -print)
echo "  [OK]   every CI shell script passes bash -n"

docker compose \
  --file provisioning/roles/sql-injection-lab/files/Labsetup/docker-compose.yml \
  config --quiet
echo "  [OK]   Docker Compose configuration is valid"

ANSIBLE_TEST_DIR="$(mktemp -d)"
trap 'rm -rf -- "$ANSIBLE_TEST_DIR"' EXIT
ansible-galaxy install \
  --role-file provisioning/requirements.yml \
  --roles-path "$ANSIBLE_TEST_DIR/roles" >/dev/null
ANSIBLE_ROLES_PATH="$REPO_ROOT/provisioning/roles:$ANSIBLE_TEST_DIR/roles" \
  ansible-playbook provisioning/playbook.yml \
  --inventory ci/inventory.yml \
  --syntax-check >/dev/null
echo "  [OK]   Ansible playbook syntax is valid with declared roles"

bash ci/checker_contract.sh
