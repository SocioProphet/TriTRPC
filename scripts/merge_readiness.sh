#!/usr/bin/env bash
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: scripts/merge_readiness.sh <source-branch> [target-branch]

Performs a non-destructive merge readiness check:
  1) Ensures working tree is clean.
  2) Confirms source/target branches exist locally.
  3) Checks out target and attempts a --no-commit merge.
  4) Runs make verify (or make test when verify is unavailable).
  5) Aborts the merge and returns to the original branch.

Examples:
  scripts/merge_readiness.sh work main
  scripts/merge_readiness.sh feature/new-fixtures
USAGE
}

if [[ ${1:-} == "-h" || ${1:-} == "--help" || $# -lt 1 || $# -gt 2 ]]; then
  usage
  exit $([[ $# -ge 1 ]] && echo 0 || echo 1)
fi

SOURCE_BRANCH="$1"
TARGET_BRANCH="${2:-main}"
ORIGINAL_BRANCH="$(git branch --show-current)"

if [[ -z "$ORIGINAL_BRANCH" ]]; then
  echo "Unable to determine current branch." >&2
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

cleanup() {
  set +e
  if git rev-parse -q --verify MERGE_HEAD >/dev/null 2>&1; then
    git merge --abort >/dev/null 2>&1
  fi
  git switch "$ORIGINAL_BRANCH" >/dev/null 2>&1
}
trap cleanup EXIT

echo "Switching to target branch: $TARGET_BRANCH"
git switch "$TARGET_BRANCH" >/dev/null

echo "Attempting non-committing merge from '$SOURCE_BRANCH' into '$TARGET_BRANCH'"
if ! git merge --no-commit --no-ff "$SOURCE_BRANCH"; then
  echo "Merge conflicts detected. Aborting merge." >&2
  exit 1
fi

echo "Merge applied cleanly. Running project checks..."
if command -v make >/dev/null 2>&1; then
  if make -qp | awk -F: '/^[a-zA-Z0-9_.-]+:/ {print $1}' | grep -qx 'verify'; then
    make verify
  elif make -qp | awk -F: '/^[a-zA-Z0-9_.-]+:/ {print $1}' | grep -qx 'test'; then
    make test
  else
    echo "No 'verify' or 'test' target found; skipping checks."
  fi
else
  echo "'make' not available; skipping checks."
fi

echo "Merge readiness check passed for '$SOURCE_BRANCH' -> '$TARGET_BRANCH'."
