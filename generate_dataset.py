#!/usr/bin/env python3
"""Unified launcher for database and telecom security trace datasets."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from db_data_generator.generate_dataset import DEFAULT_CONFIG as DB_CONFIG
from db_data_generator.generate_dataset import dataset_cases as expand_database
from db_data_generator.generate_dataset import generate_cases as generate_database
from db_data_generator.generate_dataset import public_item as public_database
from db_data_generator.generate_dataset import run_generation as run_database
from telcosecgen.engine import CONTEXTS, VERDICTS, GenerationError
from telcosecgen.engine import generate_dataset as generate_telecom
from telcosecgen.engine import load_config as load_telecom_config
from telcosecgen.engine import serialize_dataset as serialize_telecom
from telcosecgen.engine import dataset_cases as expand_telecom
from telcosecgen.engine import public_case as public_telecom
from security_trace_format import validate_global_similarity


def generate_joint_datasets(database_total: int, telecom_total: int, seed: int = 42):
    """Generate both domains against one cumulative similarity pool."""
    database_cases=generate_database(database_total,seed)
    database_items=[public_database(case) for case in expand_database(database_cases)]
    telecom_cases,telecom_plan=generate_telecom(telecom_total,seed,similarity_pool=database_items)
    telecom_items=[public_telecom(case) for case in expand_telecom(telecom_cases,database_items)]
    audit=validate_global_similarity([*database_items,*telecom_items])
    return database_cases,telecom_cases,telecom_plan,audit


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
        destination.write_text(serialize_telecom(cases,args.cases), encoding="utf-8")
    except (GenerationError, ValueError, RuntimeError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print("Generation complete")
    print(f"Domain: telecom\nRequested items: {args.cases}\nSource items: {len(cases)}")
    for verdict in VERDICTS:
        print(f"Source {verdict}: {plan['verdicts'][verdict]}")
    print(f"Benign twins: {plan['adjacency']['selected']}")
    print(f"Serialized items: {len(cases) + plan['adjacency']['selected']}")
    for verdict in VERDICTS:
        print(f"Final {verdict}: {plan['final_verdicts'][verdict]}")
    for context in CONTEXTS:
        print(f"{context}: {plan['contexts'][context]}")
    audit = plan["diversity"]
    print(f"Exact normalized duplicates: {audit['exact_normalized_duplicates']}")
    print(f"Pairs checked: {audit['pairs_checked']}")
    print(f"Pairs below threshold: {audit['pairs_below_threshold']}")
    print(f"Minimum pairwise distance: {audit['minimum_pairwise_distance']:.6f}")
    print(f"Closest pair: {audit['closest_pair']}")
    print(f"Largest mission-template cluster: {audit['largest_mission_template_cluster']}")
    print(f"Event-order duplicate groups: {audit['event_order_duplicate_groups']}")
    print(f"Unique allowed-role profiles: {audit['unique_allowed_role_profiles']}")
    print(f"Unique forbidden-role profiles: {audit['unique_forbidden_role_profiles']}")
    print(f"Pairwise diversity >= {config['diversity']['minimum_pairwise_distance']:.2f}: passed\nValidation: passed")
    print(f"Output: {destination}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
