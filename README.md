# Synthetic Security Data Generators

Both domains are exposed through one validated pipeline:

```bash
python3 generate_dataset.py --domain database --cases 250 --output database.yaml --seed 42
python3 generate_dataset.py --domain telecom --cases 250 --output telecom.yaml --seed 42
```

The generators plan exact distributions, build structured traces, enforce global
pairwise diversity, perform bounded regeneration, selectively arrange existing
benign cases next to severe examples, and validate the final ordering before
writing YAML. Counterfactual sections are not generated.

Configuration defaults live in `telcosecgen/config.json`. Run the automated suite
from the workspace root with:

```bash
python3 -m unittest discover -v
```

Python 3.10+ and PyYAML 6.0.1 are supported. See `ARCHITECTURE.md` for validation
boundaries and data flow.
