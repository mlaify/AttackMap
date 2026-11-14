#!/usr/bin/env bash
# Creates (or updates) the `pypi` deployment environment on each repository in repos.sh, and prints
# the values for PyPI's pending trusted publisher form.
#
# Run it logged in to gh as a repository admin (the operator):
#   scripts/pypi/setup-environments.sh                    # every repository in repos.sh
#   scripts/pypi/setup-environments.sh attackmap-analyzer-go
#
# The environment matches `release`: required reviewer $REVIEWER, no self-review block, and it
# deploys only from the `main` branch (manual runs that publish an existing release) and `v*` tags.
# Running it again changes nothing that is already set; it only adds missing branch policies.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/repos.sh"

die() { echo "setup-environments: $*" >&2; exit 1; }
command -v gh >/dev/null || die "gh is not installed"

repos=("$@")
[ ${#repos[@]} -gt 0 ] || repos=("${ANALYZERS[@]}" "$CORE")

reviewer_id=$(gh api "users/$REVIEWER" --jq .id)

for repo in "${repos[@]}"; do
  [[ $repo =~ ^[A-Za-z0-9_.-]+$ ]] || die "not a repository name: $repo"
  r="$OWNER/$repo"
  [ "$(gh api "repos/$r" --jq .permissions.admin)" = true ] || die "you are not an admin of $r"

  gh api -X PUT "repos/$r/environments/pypi" --input - >/dev/null <<EOF
{
  "wait_timer": 0,
  "prevent_self_review": false,
  "reviewers": [{"type": "User", "id": $reviewer_id}],
  "deployment_branch_policy": {"protected_branches": false, "custom_branch_policies": true}
}
EOF

  existing=$(gh api "repos/$r/environments/pypi/deployment-branch-policies" --jq '.branch_policies[] | "\(.type) \(.name)"')
  for policy in "branch main" "tag v*"; do
    if ! grep -qxF "$policy" <<<"$existing"; then
      gh api -X POST "repos/$r/environments/pypi/deployment-branch-policies" \
        -f type="${policy%% *}" -f name="${policy#* }" >/dev/null
    fi
  done

  # Read back what GitHub now holds.
  reviewers=$(gh api "repos/$r/environments/pypi" \
    --jq '[.protection_rules[] | select(.type == "required_reviewers") | .reviewers[].reviewer.login] | join(",")')
  policies=$(gh api "repos/$r/environments/pypi/deployment-branch-policies" \
    --jq '[.branch_policies[] | "\(.type):\(.name)"] | join(",")')
  [ "$reviewers" = "$REVIEWER" ] || die "$r: pypi reviewers are '$reviewers', expected $REVIEWER"
  echo "$r: pypi environment ok (reviewers $reviewers; deploys from $policies)"
done

cat <<EOF

Next, add a pending trusted publisher for each project on PyPI (there is no API for this):
  https://pypi.org/manage/account/publishing/   ->  "GitHub" tab, one form per row:

EOF
printf '  %-34s %-8s %-34s %-12s %s\n' "PyPI project name" Owner Repository Workflow Environment
for repo in "${repos[@]}"; do
  printf '  %-34s %-8s %-34s %-12s %s\n' "$(project_of "$repo")" "$OWNER" "$repo" release.yml pypi
done
echo
echo "A pending publisher does not reserve the name, so publish soon after (publish-existing-releases.sh)."
