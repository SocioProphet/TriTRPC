# Merge and implementation gates

This checklist defines what should be true before PR #34 is treated as an accepted unified-v4 phase-2 slice and before follow-on runtime work begins.

## Merge gates for this PR

- [ ] The addendum is acceptable as unified-v4 extension material, not a detached protocol branch.
- [ ] The fixture shapes are stable enough to serve as review artifacts.
- [ ] The benchmark scenario and harness templates are sufficient to define the intended comparison regime.
- [ ] `topic26_proposed_v3` and `kind243_extensions_proposed_v1` are acceptable as staged drafts.

## Post-merge implementation gates

- [ ] Decide whether topic26 remains the preferred mature direction or whether a narrower interim topic25 step is needed.
- [ ] Decide which proposed KIND243 extensions should advance into guarded implementation.
- [ ] Freeze the fixture shapes that are stable enough for runtime tests.
- [ ] Wire the benchmark harness into actual capture generation.

## First implementation slice

The safest first implementation slice remains:
- parse typed beacon refs without changing the hot frame shape
- accept semaphore/barrier fixture files in reference tooling
- wire benchmark harness inputs into existing comparison tooling

## Second implementation slice

After the first slice is stable:
- implement typed semantic delta carriage
- implement semaphore lifecycle events
- generate fresh measured benchmark captures
- compare against baselines using the same scenario definitions
