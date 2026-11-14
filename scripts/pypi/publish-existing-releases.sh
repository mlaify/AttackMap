#!/usr/bin/env bash
# Puts releases that already exist on PyPI: runs each repository's release.yml by hand
# (workflow_dispatch, tag = its latest GitHub release), which runs only the `pypi` job.
#
#   scripts/pypi/publish-existing-releases.sh attackmap-analyzer-rust attackmap-analyzer-swift
#   scripts/pypi/publish-existing-releases.sh            # every repository in repos.sh, AttackMap last
#   scripts/pypi/publish-existing-releases.sh --yes ...  # skip the confirmation
#
# Before a repository can be published: its `pypi` environment exists (setup-environments.sh), the
# release.yml on main has the `pypi` job, and PyPI has a (pending) trusted publisher for it.
#
# Each run waits in the `pypi` environment for approval. Logged in to gh as the required reviewer,
# the script approves the runs it started (and only those); logged in as anyone else, it prints the
# run links and waits for you to approve them in the Actions UI.
#
# After each upload it checks that PyPI's files have the same sha256 as the GitHub release's assets.
# Repositories whose version is already on PyPI are checked and skipped.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/repos.sh"

die() { echo "publish: $*" >&2; exit 1; }
[ "${BASH_VERSINFO[0]}" -ge 4 ] || die "needs bash 4 or later (macOS: brew install bash)"
for tool in gh curl python3; do command -v "$tool" >/dev/null || die "$tool is not installed"; done

yes=false
if [ "${1:-}" = --yes ]; then yes=true; shift; fi
repos=("$@")
[ ${#repos[@]} -gt 0 ] || repos=("${ANALYZERS[@]}" "$CORE")
# AttackMap goes last, whatever order it was given in.
ordered=()
for r in "${repos[@]}"; do [ "$r" = "$CORE" ] || ordered+=("$r"); done
for r in "${repos[@]}"; do [ "$r" = "$CORE" ] && ordered+=("$r"); done
repos=("${ordered[@]}")

me=$(gh api user --jq .login)

# Prints "<filename> <sha256>" lines for a version on PyPI, nothing if the version isn't there.
pypi_files() {
  curl -sf "https://pypi.org/pypi/$1/$2/json" | python3 -I -c '
import json, sys
for u in json.load(sys.stdin)["urls"]:
    print(u["filename"], u["digests"]["sha256"])
' 2>/dev/null || true
}

# Prints "<filename> <sha256>" lines for the wheel and sdist attached to a GitHub release.
release_files() {
  gh api "repos/$OWNER/$1/releases/tags/$2" \
    --jq '.assets[] | select(.name | endswith(".whl") or endswith(".tar.gz")) | "\(.name) \(.digest | sub("^sha256:"; ""))"'
}

same_files() { [ "$(pypi_files "$1" "$2" | sort)" = "$(release_files "$3" "$4" | sort)" ]; }

# --- preflight -------------------------------------------------------------------------------
declare -A TAG PROJECT VER
todo=()
echo "Checking ${#repos[@]} repositories as $me..."
for repo in "${repos[@]}"; do
  [[ $repo =~ ^[A-Za-z0-9_.-]+$ ]] || die "not a repository name: $repo"
  r="$OWNER/$repo"
  tag=$(gh release view -R "$r" --json tagName --jq .tagName) || die "$r has no release"
  project=$(project_of "$repo")
  ver=${tag#v}
  TAG[$repo]=$tag PROJECT[$repo]=$project VER[$repo]=$ver

  gh api "repos/$r/environments/pypi" --jq '[.protection_rules[] | select(.type == "required_reviewers") | .reviewers[].reviewer.login] | index("'"$REVIEWER"'")' \
    2>/dev/null | grep -qx '[0-9][0-9]*' || die "$r: no pypi environment with reviewer $REVIEWER (run setup-environments.sh)"
  gh api -H 'Accept: application/vnd.github.raw' "repos/$r/contents/.github/workflows/release.yml?ref=main" \
    | grep -q '^  pypi:$' || die "$r: release.yml on main has no pypi job (merge the pypi-publish PR)"
  [ -n "$(release_files "$repo" "$tag")" ] || die "$r $tag: the release has no wheel or sdist"

  if [ -n "$(pypi_files "$project" "$ver")" ]; then
    same_files "$project" "$ver" "$repo" "$tag" || die "$project $ver is on PyPI with different files than $r $tag"
    echo "  $project $ver: already on PyPI with the release's files, skipped"
  else
    echo "  $project $ver: to publish from $r $tag"
    todo+=("$repo")
  fi
done
[ ${#todo[@]} -gt 0 ] || { echo "Nothing to publish."; exit 0; }

if ! $yes; then
  read -r -p "Publish ${#todo[@]} release(s) to PyPI? Uploads can't be replaced. [y/N] " answer
  [[ $answer =~ ^[Yy]$ ]] || die "stopped"
fi

# --- publish ---------------------------------------------------------------------------------
# Starts the run and prints its id: the newest workflow_dispatch run by $me newer than the one before.
dispatch() {
  local r="$OWNER/$1" before id
  before=$(gh run list -R "$r" -w release.yml -e workflow_dispatch -u "$me" -L 1 --json databaseId --jq '.[0].databaseId // 0')
  gh workflow run release.yml -R "$r" --ref main -f tag="${TAG[$1]}" >/dev/null
  for _ in $(seq 30); do
    id=$(gh run list -R "$r" -w release.yml -e workflow_dispatch -u "$me" -L 1 --json databaseId --jq '.[0].databaseId // 0')
    if [ "$id" -gt "$before" ]; then echo "$id"; return; fi
    sleep 2
  done
  die "$r: the run did not appear"
}

# Approves the run's wait on the pypi environment (only pypi, only this run).
approve() {
  local r="$OWNER/$1" run=$2 env_id
  for _ in $(seq 60); do
    env_id=$(gh api "repos/$r/actions/runs/$run/pending_deployments" \
      --jq '.[] | select(.environment.name == "pypi" and .current_user_can_approve) | .environment.id')
    if [ -n "$env_id" ]; then
      gh api -X POST "repos/$r/actions/runs/$run/pending_deployments" -F "environment_ids[]=$env_id" \
        -f state=approved -f comment="PyPI: publish ${TAG[$1]} (publish-existing-releases.sh)" >/dev/null
      echo "  $1: approved run $run"
      return
    fi
    [ "$(gh run view "$run" -R "$r" --json status --jq .status)" = completed ] && return
    sleep 2
  done
  die "$r: run $run never waited on the pypi environment"
}

publish_batch() {
  local repo
  declare -A RUN
  for repo in "$@"; do
    RUN[$repo]=$(dispatch "$repo")
    echo "  $repo ${TAG[$repo]}: https://github.com/$OWNER/$repo/actions/runs/${RUN[$repo]}"
  done
  if [ "$me" = "$REVIEWER" ]; then
    for repo in "$@"; do approve "$repo" "${RUN[$repo]}"; done
  else
    echo "  Waiting for $REVIEWER to approve the runs above (environment pypi)..."
  fi
  for repo in "$@"; do
    gh run watch "${RUN[$repo]}" -R "$OWNER/$repo" --exit-status >/dev/null \
      || die "$repo: run ${RUN[$repo]} failed: gh run view ${RUN[$repo]} -R $OWNER/$repo --log-failed"
    # PyPI's JSON API is cached; give it a few minutes.
    for _ in $(seq 30); do
      same_files "${PROJECT[$repo]}" "${VER[$repo]}" "$repo" "${TAG[$repo]}" && break
      sleep 10
    done
    same_files "${PROJECT[$repo]}" "${VER[$repo]}" "$repo" "${TAG[$repo]}" \
      || die "${PROJECT[$repo]} ${VER[$repo]}: PyPI's files don't match the release (yet?)"
    echo "  ${PROJECT[$repo]} ${VER[$repo]}: on PyPI, same sha256 as the release"
  done
}

analyzers=() core=()
for repo in "${todo[@]}"; do [ "$repo" = "$CORE" ] && core+=("$repo") || analyzers+=("$repo"); done
[ ${#analyzers[@]} -eq 0 ] || { echo "Publishing analyzers..."; publish_batch "${analyzers[@]}"; }
[ ${#core[@]} -eq 0 ] || { echo "Publishing $CORE..."; publish_batch "${core[@]}"; }

# --- check attackmap[all] resolves from PyPI alone -------------------------------------------
if [ ${#core[@]} -gt 0 ]; then
  ver=${VER[$CORE]}
  echo "Resolving attackmap[all]==$ver from PyPI only (dry run, wheels only, nothing installed)..."
  venv=$(mktemp -d)
  trap 'rm -rf "$venv"' EXIT
  python3 -m venv "$venv"
  "$venv/bin/pip" install -q --dry-run --only-binary :all: --index-url https://pypi.org/simple/ \
    "attackmap[all]==$ver" && echo "  attackmap[all]==$ver resolves from PyPI"
fi
echo "Done."
