#!/usr/bin/env bash
# Approves a round of tag releases in one go: the `release` and then the `pypi` wait of each
# repository's release.yml run, instead of two clicks per repository in the Actions UI.
#
#   scripts/pypi/approve-releases.sh                  # every repository in repos.sh
#   scripts/pypi/approve-releases.sh attackmap-analyzer-go AttackMap
#   scripts/pypi/approve-releases.sh --yes            # skip the confirmation
#
# Run it logged in to gh as the required reviewer ($REVIEWER in repos.sh), after the release tags
# are pushed. It expects, for each repository, the tag v<version on main> whose version is not on
# PyPI yet; repositories whose main version is already on PyPI are skipped. It approves a run only
# when all of these hold, and stops before approving anything if one doesn't:
#   - the run is release.yml, started by pushing that tag (not by hand), and is waiting;
#   - the tag is an annotated tag whose signature GitHub verifies, on the run's commit;
#   - that commit is on main, and the version in its pyproject (AttackMap: __init__.py) is the tag's;
#   - AttackMap only: every analyzer `[all]` pins at that commit is on PyPI before its `pypi`
#     wait is approved (the analyzers in this round go first, so this holds once they are done).
# It shows the list and asks once. After each run it checks that PyPI's files have the same sha256
# as the GitHub release's, and for AttackMap that `attackmap[all]` resolves from PyPI alone.
set -euo pipefail
here=$(cd "$(dirname "$0")" && pwd)
. "$here/repos.sh"

die() { echo "approve: $*" >&2; exit 1; }
[ "${BASH_VERSINFO[0]}" -ge 4 ] || die "needs bash 4 or later (macOS: brew install bash)"
for tool in gh curl python3; do command -v "$tool" >/dev/null || die "$tool is not installed"; done

yes=false
if [ "${1:-}" = --yes ]; then yes=true; shift; fi
repos=("$@")
[ ${#repos[@]} -gt 0 ] || repos=("${ANALYZERS[@]}" "$CORE")

me=$(gh api user --jq .login)
[ "$me" = "$REVIEWER" ] || die "logged in to gh as $me; log in as the required reviewer $REVIEWER"

on_pypi() { curl -sf -o /dev/null "https://pypi.org/pypi/$1/$2/json"; }

pypi_files() {
  curl -sf "https://pypi.org/pypi/$1/$2/json" | python3 -I -c '
import json, sys
for u in json.load(sys.stdin)["urls"]:
    print(u["filename"], u["digests"]["sha256"])
' 2>/dev/null || true
}

release_files() {
  gh api "repos/$OWNER/$1/releases/tags/$2" \
    --jq '.assets[] | select(.name | endswith(".whl") or endswith(".tar.gz")) | "\(.name) \(.digest | sub("^sha256:"; ""))"'
}

raw() { gh api -H 'Accept: application/vnd.github.raw' "repos/$OWNER/$1/contents/$2?ref=$3"; }

# The package version at a commit.
version_at() {
  if [ "$1" = "$CORE" ]; then
    raw "$1" src/attackmap/__init__.py "$2" | sed -n 's/^__version__ = "\(.*\)"$/\1/p'
  else
    raw "$1" pyproject.toml "$2" | sed -n 's/^version = "\(.*\)"$/\1/p'
  fi
}

# --- preflight -------------------------------------------------------------------------------
declare -A TAG VER PROJECT RUN SHA
todo=()
echo "Checking ${#repos[@]} repositories as $me..."
for repo in "${repos[@]}"; do
  [[ $repo =~ ^[A-Za-z0-9_.-]+$ ]] || die "not a repository name: $repo"
  r="$OWNER/$repo"
  project=$(project_of "$repo")
  ver=$(version_at "$repo" main)
  [ -n "$ver" ] || die "$r: no version on main"
  if on_pypi "$project" "$ver"; then
    echo "  $project $ver: already on PyPI, skipped"
    continue
  fi
  tag="v$ver"

  run=$(gh api "repos/$r/actions/workflows/release.yml/runs?event=push&status=waiting" \
    --jq "[.workflow_runs[] | select(.head_branch == \"$tag\")] | .[0].id // empty")
  [ -n "$run" ] || die "$r: no release.yml run for $tag is waiting (push the tag first)"
  sha=$(gh api "repos/$r/actions/runs/$run" --jq .head_sha)

  ref=$(gh api "repos/$r/git/ref/tags/$tag" --jq '.object.type + " " + .object.sha') || die "$r: no tag $tag"
  [ "${ref%% *}" = tag ] || die "$r $tag: not an annotated tag"
  verified=$(gh api "repos/$r/git/tags/${ref#* }" --jq '"\(.verification.verified) \(.object.sha)"')
  [ "$verified" = "true $sha" ] || die "$r $tag: signature not verified, or the tag isn't on the run's commit"
  status=$(gh api "repos/$r/compare/$sha...main" --jq .status)
  [[ $status =~ ^(identical|ahead)$ ]] || die "$r $tag: commit ${sha:0:7} is not on main"
  [ "$(version_at "$repo" "$sha")" = "$ver" ] || die "$r $tag: the version at ${sha:0:7} is not $ver"

  TAG[$repo]=$tag VER[$repo]=$ver PROJECT[$repo]=$project RUN[$repo]=$run SHA[$repo]=$sha
  echo "  $project $ver: run $run, signed tag $tag on main at ${sha:0:7}"
  todo+=("$repo")
done
[ ${#todo[@]} -gt 0 ] || { echo "Nothing to approve."; exit 0; }

if ! $yes; then
  read -r -p "Approve ${#todo[@]} release(s): GitHub release, then PyPI (uploads can't be replaced)? [y/N] " answer
  [[ $answer =~ ^[Yy]$ ]] || die "stopped"
fi

# --- approve ---------------------------------------------------------------------------------
# Every analyzer pinned in AttackMap's [all] at the release commit is on PyPI.
pins_on_pypi() {
  local pin
  for pin in $(raw "$CORE" pyproject.toml "${SHA[$CORE]}" | grep -oE 'attackmap-analyzer-[a-z-]+==[0-9][0-9.]*'); do
    on_pypi "${pin%%==*}" "${pin#*==}" || return 1
  done
}

# Drives the runs of the given repositories to the end, approving each environment wait once.
drive() {
  local repo r run state envs env id left deadline=$((SECONDS + 3600))
  declare -A done_env
  while :; do
    left=0
    for repo in "$@"; do
      r="$OWNER/$repo" run=${RUN[$repo]}
      [ -z "${done_env[$repo:finished]:-}" ] || continue
      state=$(gh api "repos/$r/actions/runs/$run" --jq '"\(.status) \(.conclusion)"')
      if [ "${state% *}" = completed ]; then
        [ "${state#* }" = success ] || die "$r: run $run failed: gh run view $run -R $r --log-failed"
        done_env[$repo:finished]=1
        continue
      fi
      left=$((left + 1))
      [ "${state% *}" = waiting ] || continue
      envs=$(gh api "repos/$r/actions/runs/$run/pending_deployments" \
        --jq '.[] | select(.current_user_can_approve) | "\(.environment.name) \(.environment.id)"')
      while read -r env id; do
        [ -n "$env" ] && [ -z "${done_env[$repo:$env]:-}" ] || continue
        [[ $env =~ ^(release|pypi)$ ]] || die "$r: run $run waits on an unexpected environment: $env"
        if [ "$repo" = "$CORE" ] && [ "$env" = pypi ] && ! pins_on_pypi; then
          continue  # the analyzers aren't all on PyPI yet
        fi
        gh api -X POST "repos/$r/actions/runs/$run/pending_deployments" -F "environment_ids[]=$id" \
          -f state=approved -f comment="${TAG[$repo]}: $env (approve-releases.sh)" >/dev/null
        done_env[$repo:$env]=1
        echo "  $repo ${TAG[$repo]}: approved $env"
      done <<<"$envs"
    done
    [ "$left" -gt 0 ] || break
    [ $SECONDS -lt $deadline ] || die "runs still not done after an hour"
    sleep 10
  done
  for repo in "$@"; do
    for _ in $(seq 30); do  # PyPI's JSON API is cached; give it a few minutes.
      [ "$(pypi_files "${PROJECT[$repo]}" "${VER[$repo]}" | sort)" = "$(release_files "$repo" "${TAG[$repo]}" | sort)" ] && break
      sleep 10
    done
    [ "$(pypi_files "${PROJECT[$repo]}" "${VER[$repo]}" | sort)" = "$(release_files "$repo" "${TAG[$repo]}" | sort)" ] \
      || die "${PROJECT[$repo]} ${VER[$repo]}: PyPI's files don't match the release (yet?)"
    echo "  ${PROJECT[$repo]} ${VER[$repo]}: on PyPI, same sha256 as the release"
  done
}

analyzers=() core=()
for repo in "${todo[@]}"; do [ "$repo" = "$CORE" ] && core+=("$repo") || analyzers+=("$repo"); done
[ ${#analyzers[@]} -eq 0 ] || { echo "Releasing analyzers..."; drive "${analyzers[@]}"; }
[ ${#core[@]} -eq 0 ] || { echo "Releasing $CORE..."; drive "${core[@]}"; }

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
