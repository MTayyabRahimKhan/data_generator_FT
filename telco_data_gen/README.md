# Legacy Telecom Security Dataset Generator

This directory contains the earlier four-label prototype. The supported telecom
security judge generator is now `telcosecgen` at the workspace root:

```bash
python3 -m telcosecgen generate --cases 250 --output telecom_dataset.yaml --seed 42
```

The new command implements the five-verdict taxonomy, independent mission
outcomes, embedded benign counterfactuals, and the complete validation pipeline.

## Legacy usage

This zero-dependency Python generator creates distinct telecom trace-evaluation cases from the requirements in `goal.txt`. It covers RAN, 5G/4G packet core, subscriber/SIM, Transport IP/MPLS, and IMS/operations scenarios.

## Generate data

Edit `total_cases` in `config.json`, then run one command from this folder:

```bash
python3 generate.py
```

The default output is `telecom_security_cases.txt`. For a one-off size without editing the config:

```bash
python3 generate.py --count 500
```

Other useful overrides:

```bash
python3 generate.py --count 200 --output generated/cases-200.txt --seed 1234
```

The default percentages are 70% aligned, 15% single-event violations, 10% contextual violations, and 5% threat/escalation cases. Counts for totals not divisible by 100 use deterministic largest-remainder rounding and always add up to `total_cases`.

Set `shuffle_cases` to `true` to mix categories. The same config and seed always produce the same data.

## Validate the generator

```bash
python3 -m unittest -v
```

No third-party packages are required. Python 3.10 or newer is supported.
