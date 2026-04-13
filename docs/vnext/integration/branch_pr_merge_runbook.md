# Branch + PR Integration Runbook (to land in `main` safely)

This runbook is the operational counterpart to the unified spec crosswalk. Use it when you are about to fold multi-day branch and PR work into `main`.

## Goal

Integrate all accepted work into `main` while minimizing risk of dropped commits, accidental regressions, or merge drift.

## 0) Preconditions

- You are on a clean working tree.
- `main` and the source branch (usually `work`) both exist locally.
- You can run the audit script from repo root.

## 1) Verify source/target history relationship first

```bash
./tools/audit_branch_pr_integration.sh main work
```

Interpretation:

- **SAFE FAST-FORWARD**: use `--ff-only` merge.
- **ALREADY INTEGRATED**: no merge needed.
- **DIVERGED**: inspect and resolve manually before merge.

## 2) Review PR lineage visibility

The audit prints all merge commits visible in source history (including `Merge pull request #...` entries). Confirm expected PRs appear before landing.

## 3) Run verification checks before merge

```bash
make verify
```

If dependency/network limits block language tests, at minimum keep a record of what failed and why before proceeding.

## 4) Perform merge

Fast-forward path (preferred when audit says safe):

```bash
git checkout main
git merge --ff-only work
```

Diverged path:

```bash
git checkout main
git merge --no-ff work
```

Then resolve conflicts and re-run checks.

## 5) Post-merge confirmation

```bash
./tools/audit_branch_pr_integration.sh main main
```

This should show `ALREADY INTEGRATED` (or zero missing commits).

## 6) Recovery anchors (recommended)

Before merge, create a safety tag on both refs:

```bash
git tag pre-main-merge-main-$(date +%Y%m%d) main
git tag pre-main-merge-work-$(date +%Y%m%d) work
```

This gives a deterministic rollback point if you need to unwind quickly.
