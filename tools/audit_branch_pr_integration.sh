#!/usr/bin/env bash
set -euo pipefail

TARGET_BRANCH="${1:-main}"
SOURCE_REF="${2:-HEAD}"

if ! git rev-parse --verify "$SOURCE_REF" >/dev/null 2>&1; then
  echo "ERROR: source ref '$SOURCE_REF' does not exist."
  exit 2
fi

if ! git rev-parse --verify "$TARGET_BRANCH" >/dev/null 2>&1; then
  echo "ERROR: target branch '$TARGET_BRANCH' does not exist locally."
  echo "Hint: create it (e.g., git branch $TARGET_BRANCH <base>) or fetch it from origin."
  exit 2
fi

SOURCE_SHA="$(git rev-parse --short "$SOURCE_REF")"
TARGET_SHA="$(git rev-parse --short "$TARGET_BRANCH")"

echo "=== TriTRPC Branch/PR Integration Audit ==="
echo "Target branch : $TARGET_BRANCH ($TARGET_SHA)"
echo "Source ref    : $SOURCE_REF ($SOURCE_SHA)"
echo

echo "--- Merge commits in source history (newest first) ---"
git log --merges --pretty=format:'%h %s' "$SOURCE_REF"
echo

MISSING_COMMITS="$(git rev-list --count "$TARGET_BRANCH..$SOURCE_REF")"
echo "--- Commits in $SOURCE_REF but not yet in $TARGET_BRANCH ---"
echo "$MISSING_COMMITS"

if [ "$MISSING_COMMITS" -gt 0 ]; then
  git log --oneline "$TARGET_BRANCH..$SOURCE_REF"
else
  echo "None. Target already contains source history."
fi

echo
COMMON_BASE="$(git merge-base "$TARGET_BRANCH" "$SOURCE_REF")"
COMMON_BASE_SHORT="$(git rev-parse --short "$COMMON_BASE")"
echo "Merge base: $COMMON_BASE_SHORT"

if git merge-base --is-ancestor "$TARGET_BRANCH" "$SOURCE_REF"; then
  echo "Status: SAFE FAST-FORWARD (target is ancestor of source)."
  echo "Suggested merge command: git checkout $TARGET_BRANCH && git merge --ff-only $SOURCE_REF"
  exit 0
fi

if git merge-base --is-ancestor "$SOURCE_REF" "$TARGET_BRANCH"; then
  echo "Status: ALREADY INTEGRATED (source is ancestor of target)."
  exit 0
fi

echo "Status: DIVERGED (manual conflict review required)."
echo "Suggested inspection:"
echo "  git log --left-right --cherry-pick --oneline $TARGET_BRANCH...$SOURCE_REF"
echo "  git diff --stat $TARGET_BRANCH...$SOURCE_REF"
exit 1
