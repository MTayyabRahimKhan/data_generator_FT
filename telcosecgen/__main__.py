"""Command-line entry point for the telecom security generator."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from .engine import CONTEXTS, VERDICTS, GenerationError, generate_dataset, load_config, serialize_dataset


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
        rendered = serialize_dataset(cases,args.cases)
        destination.write_text(rendered, encoding="utf-8")
    except (GenerationError, ValueError, OSError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 2
    print("Generation complete")
    print(f"Requested items: {args.cases}")
    print(f"Source items: {plan['source_count']}")
    for verdict in VERDICTS:
        print(f"Source {verdict}: {plan['verdicts'][verdict]}")
    print(f"Benign twins: {plan['adjacency']['selected']}")
    print(f"Serialized items: {len(cases) + plan['adjacency']['selected']}")
    for verdict in VERDICTS:
        print(f"Final {verdict}: {plan['final_verdicts'][verdict]}")
    print(f"Mission completed: {plan['outcomes']['completed']}")
    print(f"Mission failed: {plan['outcomes']['failed']}")
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
    print(f"Pairwise diversity >= {config['diversity']['minimum_pairwise_distance']:.2f}: passed")
    print("Validation: passed")
    print(f"Output: {destination}")
    if args.cases < len(VERDICTS):
        print("WARNING: Dataset size is too small to guarantee representation of all verdict categories.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
