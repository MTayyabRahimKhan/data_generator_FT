# Database Security Dataset Generator

Run the complete pipeline from the workspace root with one command:

```bash
python3 -m dbsecgen generate --cases 250 --output ./data/db_security_250.yaml --seed 42
```

`--cases` is the exact number of top-level primary cases. Counterfactuals are not
generated. Selected severe cases may be placed next to an existing benign case.
`--output` defaults to `dataset.yaml`; `--seed` defaults to `0`.

The generator deterministically apportions the five verdicts at
35/20/20/15/10, the five engines evenly, and mission outcomes near 95/5. It then
plans multi-dimensional blueprints, expands engine-aware traces, derives state
changes and authorization findings from a deterministic event registry, applies
selective adjacency, and writes YAML-compatible multi-document output separated
by `---`.

Each candidate is validated against every accepted fingerprint at the configured
minimum pairwise distance (default `0.10`). Before output, all pairs are audited
again: 500 cases means 124,750 comparisons and 1,000 cases means 499,500.
Mission-template families are capped at 5% for datasets of at least 100 cases;
event-cycle and explanation-reuse checks are also configurable.

Configuration and policy percentages live in `generator_config.json`. Invalid,
zero, negative, and non-integer case counts are rejected.

Run the automated suite from the workspace root:

```bash
python3 -m unittest discover -s db_data_generator -v
```
