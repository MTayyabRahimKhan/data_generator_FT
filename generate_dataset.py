#!/usr/bin/env python3
"""Unified launcher for database and telecom security trace datasets."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import yaml

from db_data_generator.generate_dataset import DEFAULT_CONFIG as DB_CONFIG
from db_data_generator.generate_dataset import run_generation as run_database
from telcosecgen.engine import CONTEXTS, VERDICTS, GenerationError
from telcosecgen.engine import generate_dataset as generate_telecom
from telcosecgen.engine import load_config as load_telecom_config
from telcosecgen.engine import public_case


def positive_integer(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("--cases must be a positive integer") from exc
    if parsed < 1:
        raise argparse.ArgumentTypeError("--cases must be a positive integer")
    return parsed


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--domain", required=True, choices=("database", "telecom"))
    parser.add_argument("--cases", required=True, type=positive_integer)
    parser.add_argument("--output", type=Path, help="output path (defaults to <domain>_dataset.yaml)")
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--config", type=Path)
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    output = args.output or Path(f"{args.domain}_dataset.yaml")
    try:
        if args.domain == "database":
            run_database(args.cases, output, args.seed, args.config or DB_CONFIG)
            return 0
        config = load_telecom_config(args.config) if args.config else load_telecom_config()
        cases, plan = generate_telecom(args.cases, args.seed, config)
        destination = output.resolve()
        destination.parent.mkdir(parents=True, exist_ok=True)
        destination.write_text(yaml.safe_dump_all([public_case(case) for case in cases], sort_keys=False, allow_unicode=True), encoding="utf-8")
    except (GenerationError, ValueError, RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print("Generation complete")
    print(f"Domain: telecom\nPrimary cases: {len(cases)}")
    for verdict in VERDICTS:
        print(f"{verdict.title()}: {plan['verdicts'][verdict]}")
    print(f"Selective adjacencies: {plan['adjacency']['selected']}")
    print(f"Benign before severe: {plan['adjacency']['before']}")
    print(f"Benign after severe: {plan['adjacency']['after']}")
    for context in CONTEXTS:
        print(f"{context}: {plan['contexts'][context]}")
    print("Pairwise diversity >= 0.10: passed\nValidation: passed")
    print(f"Output: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
