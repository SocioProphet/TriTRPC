#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/safe_merge.sh <source-branch> [target-branch]

Safely merge a source branch into a target branch (default: current branch):
  1) Ensures working tree is clean.
  2) Confirms both branches exist locally.
  3) Fast-forwards target from its upstream when configured.
  4) Merges source branch with --no-ff.
  5) Runs lightweight checks when available.

Examples:
  scripts/safe_merge.sh feature/api-hardening
  scripts/safe_merge.sh release/2026-04 work
USAGE
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit $([[ $# -ge 1 ]] && echo 0 || echo 1)
fi

SOURCE_BRANCH="$1"
TARGET_BRANCH="${2:-$(git branch --show-current)}"

if [[ -z "$TARGET_BRANCH" ]]; then
  echo "Unable to determine target branch. Pass it explicitly as arg #2." >&2
  exit 1
fi

if [[ -n "$(git status --porcelain)" ]]; then
  echo "Working tree is not clean. Commit or stash changes first." >&2
  exit 1
fi

if ! git show-ref --verify --quiet "refs/heads/$SOURCE_BRANCH"; then
  echo "Source branch '$SOURCE_BRANCH' not found locally." >&2
  exit 1
fi

if ! git show-ref --verify --quiet "refs/heads/$TARGET_BRANCH"; then
  echo "Target branch '$TARGET_BRANCH' not found locally." >&2
  exit 1
fi

echo "Switching to target branch: $TARGET_BRANCH"
git switch "$TARGET_BRANCH"

UPSTREAM_REF=""
if UPSTREAM_REF=$(git rev-parse --abbrev-ref --symbolic-full-name "${TARGET_BRANCH}@{upstream}" 2>/dev/null); then
  echo "Updating '$TARGET_BRANCH' from upstream '$UPSTREAM_REF'"
  git pull --ff-only
else
  echo "No upstream configured for '$TARGET_BRANCH'; skipping pull."
fi

echo "Merging '$SOURCE_BRANCH' into '$TARGET_BRANCH'"
git merge --no-ff "$SOURCE_BRANCH"

echo "Running available project checks..."
if command -v make >/dev/null 2>&1; then
  if make -qp | awk -F: '/^[a-zA-Z0-9_.-]+:/ {print $1}' | grep -qx 'verify'; then
    make verify || {
      echo "make verify failed after merge. Resolve issues and re-run checks." >&2
      exit 1
    }
  elif make -qp | awk -F: '/^[a-zA-Z0-9_.-]+:/ {print $1}' | grep -qx 'test'; then
    make test || {
      echo "make test failed after merge. Resolve issues and re-run checks." >&2
      exit 1
    }
  else
    echo "No 'verify' or 'test' target found; skipping checks."
  fi
else
  echo "'make' not available; skipping checks."
fi

echo "Merge complete. Review changes, then push and open a PR."
