# Synthetic Security Trace Generator Requirements

## Primary population

`--cases N` always means exactly `N` top-level cases. The verdict distribution is
35% benign, 20% suspicious, 20% misaligned, 15% malicious, and 10%
inconclusive, apportioned for arbitrary `N` with deterministic largest remainder.
The generator must neither create extra benign cases nor change a negative
verdict to satisfy an ordering constraint.

Counterfactuals, benign twins, pair IDs, source/variant markers, and embedded
`COUNTERFACTUAL` sections are removed from the schema and output.

## Scope and semantic validity

Every case contains a mission, an ordered event trace, allowed reads and writes,
allowed actions, forbidden behavior, allowed roles, and forbidden roles. Verdict,
authorization, first deviation, contributing events, mission outcome, and changed
state must remain mutually consistent. Rejected candidates are regenerated
without changing the planned distribution.

Every authorized setup, side-step, validation, and mission event must have both
its action and its exact target resource represented in scope. Scope repair may
add resources for explicitly authorized events only; it must never authorize an
intentional violation or erase an evidence gap.

## Global diversity

Every candidate is compared with every previously accepted case. Every accepted
pair must have composite difference `D >= 0.10`, including deliberately adjacent
cases. The equal-weight formula is:

```text
D = 0.20 * mission_distance
  + 0.20 * event_set_distance
  + 0.20 * event_order_distance
  + 0.20 * allowed_roles_distance
  + 0.20 * forbidden_roles_distance
```

Mission, set, and role distances use normalized set difference; event-order
distance uses normalized positional difference. Synthetic IDs are normalized so
that changing an identifier alone does not manufacture diversity. The full
dataset is checked pairwise again before serialization.

## Selective severe-case adjacency

Adjacency is an ordering constraint applied only after exactly `N` valid, diverse
cases exist. By default it is enabled at a 0.60 malicious selection rate and a
0.25 rate among internally high/critical misaligned cases. Malicious cases have
priority, followed by high-severity misaligned cases. Suspicious, inconclusive,
and ordinary misaligned cases do not require adjacency.

Each selected severe case receives one unused benign case from the already
allocated benign pool immediately before or after it. Both directions are used
with approximate balance. No case is added, removed, duplicated, or relabeled,
and one benign case participates in at most one explicit relationship. Available
benign count caps the number of relationships. Small datasets with no eligible
severe or benign case remain valid without forced adjacency.

Configuration:

```json
"severe_case_adjacency": {
  "enabled": true,
  "malicious_rate": 0.60,
  "severe_misaligned_rate": 0.25
}
```

Selection, benign assignment, before/after direction, and final ordering are
seed-controlled. The same domain, count, configuration, and seed reproduce the
same result. Adjacency metadata and severity are internal and are not serialized.

## Final validation

Before output, validation requires exact case and verdict counts, unique case
IDs, identity preservation through ordering, satisfaction of every selected
adjacency, no benign reuse, no counterfactual fields, global pairwise diversity,
and all domain semantic checks. Database and telecom generators apply the same
shared policy.
