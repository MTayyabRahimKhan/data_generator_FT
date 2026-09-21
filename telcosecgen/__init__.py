"""Synthetic telecom security data engine."""

from .engine import (
    GenerationError,
    allocate_largest_remainder,
    generate_dataset,
    load_config,
    validate_dataset,
)

__all__ = [
    "GenerationError",
    "allocate_largest_remainder",
    "generate_dataset",
    "load_config",
    "validate_dataset",
]

