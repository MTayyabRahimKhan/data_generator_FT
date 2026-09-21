"""Command-line entry point for the telecom security generator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from .engine import CONTEXTS, VERDICTS, GenerationError, generate_dataset, load_config, public_case


def positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--cases must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("--cases must be a positive integer")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="python -m telcosecgen")
    subparsers = parser.add_subparsers(dest="command", required=True)
    generate = subparsers.add_parser("generate", help="plan, generate, validate, repair, and write a dataset")
    generate.add_argument("--cases", required=True, type=positive_integer, help="number of primary cases")
    generate.add_argument("--output", required=True, type=Path, help="output YAML path")
    generate.add_argument("--seed", type=int, default=42, help="deterministic seed")
    generate.add_argument("--config", type=Path, help="configuration JSON path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    try:
        config = load_config(args.config) if args.config else load_config()
        cases, plan = generate_dataset(args.cases, args.seed, config)
        destination = args.output.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        rendered = yaml.safe_dump_all([public_case(case) for case in cases], sort_keys=False, explicit_start=False, allow_unicode=True)
        destination.write_text(rendered, encoding="utf-8")
    except (GenerationError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print("Generation complete")
    print(f"Primary cases: {args.cases}")
    for verdict in VERDICTS:
        print(f"{verdict.title()}: {plan['verdicts'][verdict]}")
    print(f"Selective adjacencies: {plan['adjacency']['selected']}")
    print(f"Benign before severe: {plan['adjacency']['before']}")
    print(f"Benign after severe: {plan['adjacency']['after']}")
    print(f"Mission completed: {plan['outcomes']['completed']}")
    print(f"Mission failed: {plan['outcomes']['failed']}")
    for context in CONTEXTS:
        print(f"{context}: {plan['contexts'][context]}")
    print("Pairwise diversity >= 0.10: passed")
    print("Validation: passed")
    print(f"Output: {destination}")
    if args.cases < len(VERDICTS):
        print("WARNING: Dataset size is too small to guarantee representation of all verdict categories.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
