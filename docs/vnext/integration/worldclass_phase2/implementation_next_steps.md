# Implementation next steps

This note records the first implementation-facing follow-on work that should come after the phase-2 review PR is accepted.

## After review of this PR

1. Decide whether `topic26_proposed_v3` remains the preferred direction or whether a narrower topic25-style interim step is required.
2. Decide which `kind243` extension values should advance from proposal to guarded implementation.
3. Freeze the fixture shapes that are stable enough to become native runtime test inputs.

## First implementation slice

The safest first runtime slice is:

- parse typed beacon refs without changing the hot frame shape
- accept semaphore/barrier fixture files in reference tooling
- wire benchmark harness inputs into existing comparison tooling

This keeps the first code step close to the review artifacts and avoids over-committing to a full runtime rewrite too early.

## Second implementation slice

After the first slice is stable:

- implement typed semantic delta carriage
- implement semaphore lifecycle events
- generate fresh measured benchmark captures
- compare against existing baselines using the same scenario definitions
