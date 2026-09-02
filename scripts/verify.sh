#!/usr/bin/env bash
set -Eeuo pipefail

repository_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$repository_root"

python3 -m unittest discover -s tests -p 'test_*.py' -v
python3 -m compileall -q scripts tests
command -v actionlint >/dev/null
actionlint
command -v shellcheck >/dev/null
shellcheck scripts/*.sh
git diff --check

python3 scripts/release_control.py validate-policy-set \
  --policy-dir policies/products
governance_readiness="$(python3 scripts/release_control.py validate-governance \
  --codeowners .github/CODEOWNERS \
  --allowed-signers policies/release-signers \
  --settings bootstrap/repository-settings.json \
  --allow-incomplete)"
printf 'governance readiness (checked-in diagnostic; live GitHub configuration is unverified): %s\n' \
  "$governance_readiness"

while IFS= read -r policy; do
  python3 scripts/release_control.py validate-policy \
    --policy "$policy" \
    --allow-disabled
done < <(find policies/products -type f \( -name '*.json' -o -name '*.json.disabled' \) -print | sort)

printf 'release-control verification passed\n'
