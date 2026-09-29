# Synthetic Security Data Generators

Both domains are exposed through one validated pipeline:

```bash
python3 generate_dataset.py --domain database --cases 250 --output database.yaml --seed 42
python3 generate_dataset.py --domain telecom --cases 250 --output telecom.yaml --seed 42
```

The generators plan exact distributions, build structured traces, enforce global
pairwise diversity during candidate acceptance and in a final all-pairs audit,
perform bounded regeneration, selectively create mission-coherent benign twins,
derive verdicts and causal explanations from finalized evidence, and validate
the final ordering before writing YAML. `family_id` groups direct twins, while
`template_family_id` supports leakage-safe template-family splitting.
Counterfactual sections are not generated.

Configuration defaults live in `telcosecgen/config.json`. Run the automated suite
from the workspace root with:

```bash
python3 -m unittest discover -v
```

Python 3.10+ and PyYAML 6.0.1 are supported. See `ARCHITECTURE.md` for validation
boundaries and data flow.
