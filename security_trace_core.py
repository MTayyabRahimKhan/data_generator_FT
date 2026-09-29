"""Shared diversity and selective-adjacency policy for security traces.

The functions in this module are deliberately domain-neutral.  Domain
generators provide small feature views and callbacks; this module owns the
cross-domain invariants that ordering never changes membership or verdicts.
"""

from __future__ import annotations

import random
import re
from collections import Counter
from dataclasses import dataclass
from functools import lru_cache
from typing import Any, Callable, Iterable, Mapping, Sequence, TypeVar


MIN_COMPOSITE_DIFFERENCE = 0.10
DIVERSITY_WEIGHTS = {
    "mission": 0.20,
    "event_set": 0.20,
    "event_order": 0.20,
    "allowed_roles": 0.20,
    "forbidden_roles": 0.20,
}


@dataclass(frozen=True)
class DiversityFeatures:
    mission: str
    events: tuple[str, ...]
    allowed_roles: tuple[str, ...]
    forbidden_roles: tuple[str, ...]


@dataclass(frozen=True)
class AdjacencyConfig:
    enabled: bool = True
    malicious_rate: float = 0.60
    severe_misaligned_rate: float = 0.25


@dataclass(frozen=True)
class AdjacencyRecord:
    severe_case_id: str
    benign_case_id: str
    direction: str
    severity_level: str


@dataclass(frozen=True)
class LimitExceedance:
    """One event metric that strictly exceeds a declared policy limit."""

    event_number: int
    event_type: str
    target: str
    metric: str
    observed: int
    maximum: int


@dataclass(frozen=True)
class BaselineOutlier:
    """One factual observation above its historical p95, not a policy breach."""

    event_number: int
    event_type: str
    target: str
    metric: str
    observed: int
    historical_p95: int


@dataclass(frozen=True)
class ApprovalEvidence:
    """Evidence about one approval explicitly required by scope."""

    event_number: int
    approval: str
    action: str
    target: str
    state: str


@dataclass(frozen=True)
class EventSemantics:
    """Deterministic state effect for one event type.

    ``changed`` means observed modifications, including attempts later reverted.
    Read-only/informational events never appear.  A rollback annotates preceding
    reversible mutations; irreversible and external effects remain persisted.
    """

    reads_state: bool = False
    mutates_state: bool = False
    mutation_kind: str = "informational"
    external_side_effect: bool = False
    reversible: bool = False
    rollback_sensitive: bool = False
    informational_only: bool = False

    @property
    def reportable(self) -> bool:
        return self.mutates_state or self.external_side_effect


READ_ONLY = EventSemantics(reads_state=True, informational_only=True)
INFORMATIONAL = EventSemantics(informational_only=True)


def state_change(kind: str, *, reversible: bool = True) -> EventSemantics:
    return EventSemantics(
        mutates_state=True,
        mutation_kind=kind,
        reversible=reversible,
        rollback_sensitive=reversible,
    )


def external_effect(kind: str) -> EventSemantics:
    return EventSemantics(
        mutation_kind=kind,
        external_side_effect=True,
        reversible=False,
        rollback_sensitive=False,
    )


def _event_value(event: Any, name: str) -> Any:
    return event[name] if isinstance(event, Mapping) else getattr(event, name)


def describe_state_effect(event: Any, semantics: EventSemantics) -> str:
    """Describe an effect from the event itself, never from a mission template."""
    kind = _event_value(event, "event_type")
    target = _event_value(event, "target")
    verbs = {
        "create": "created", "delete": "deleted", "update": "updated",
        "permission_grant": "granted permissions on",
        "permission_revoke": "revoked permissions on",
        "configuration": "changed configuration for",
        "schema_add": "added schema object on",
        "schema_drop": "removed schema object from",
        "schema_migrate": "migrated schema for",
        "data_patch": "patched data in", "data_backfill": "backfilled data in",
        "data_repair": "repaired data in", "maintenance": "performed maintenance on",
        "statistics_refresh": "refreshed persisted statistics for",
        "audit_change": "changed audit state for",
        "external_export": "wrote an external artifact to",
        "external_import": "imported an external artifact into",
        "promotion": "promoted an artifact to", "restart": "restarted",
        "acknowledgement": "acknowledged", "role_change": "changed role state for",
    }
    verb = verbs.get(semantics.mutation_kind, semantics.mutation_kind.replace("_", " "))
    return f"{verb} {target} [{kind}]"


def derive_changed(
    events: Sequence[Any],
    registry: Mapping[str, EventSemantics],
    *,
    rollback_types: frozenset[str] = frozenset({"rollback.execute", "db.transaction.rollback"}),
) -> tuple[str, ...]:
    """Derive all observed state/external effects from accepted events.

    A rollback is defined as reverting all earlier rollback-sensitive events in
    the same trace.  This matches the generators' single-transaction model.
    """
    rollback_numbers = [
        int(_event_value(event, "number"))
        for event in events
        if _event_value(event, "event_type") in rollback_types
    ]
    changed: list[str] = []
    for event in events:
        event_type = _event_value(event, "event_type")
        semantics = registry.get(event_type)
        if semantics is None:
            raise ValueError(f"missing event semantics for {event_type}")
        if not semantics.reportable:
            continue
        number = int(_event_value(event, "number"))
        description = f"event {number}: {describe_state_effect(event, semantics)}"
        reverting = next((item for item in rollback_numbers if item > number), None)
        if reverting is not None and semantics.rollback_sensitive:
            description += f"; attempted change reverted by event {reverting} rollback"
        changed.append(description)
    return tuple(changed)


def validate_changed(
    events: Sequence[Any],
    changed: Sequence[str],
    registry: Mapping[str, EventSemantics],
) -> list[str]:
    """Return deterministic changed-state consistency errors."""
    errors: list[str] = []
    try:
        expected = derive_changed(events, registry)
    except ValueError as exc:
        return [str(exc)]
    by_number = {int(_event_value(event, "number")): event for event in events}
    for entry in changed:
        match = re.match(r"^event (\d+):", entry)
        if not match:
            errors.append("changed entry has no valid event reference")
            continue
        number = int(match.group(1))
        event = by_number.get(number)
        if event is None:
            errors.append(f"changed references missing event {number}")
            continue
        semantics = registry.get(_event_value(event, "event_type"))
        if semantics is None or not semantics.reportable:
            errors.append(f"changed references read-only event {number}")
        elif describe_state_effect(event, semantics) not in entry:
            errors.append(f"changed description does not match event {number}")
    if tuple(changed) != expected:
        errors.append("changed does not exactly represent all event state effects")
    return errors


def find_action_scope_violations(
    events: Sequence[Any],
    *,
    allowed_reads: Iterable[str],
    allowed_writes: Iterable[str],
    allowed_actions: Iterable[str],
    forbidden: Iterable[str],
    registry: Mapping[str, EventSemantics],
) -> list[int]:
    """Apply forbidden, exact action, then resource authorization precedence."""
    reads, writes, actions = set(allowed_reads), set(allowed_writes), set(allowed_actions)
    denied = {item.lower() for item in forbidden}
    violations: list[int] = []
    for event in events:
        number = int(_event_value(event, "number"))
        kind = str(_event_value(event, "event_type"))
        target = str(_event_value(event, "target"))
        semantics = registry.get(kind)
        if semantics is None:
            violations.append(number)
            continue
        explicit_forbidden = kind.lower() in denied or target.lower() in denied or f"{kind}:{target}".lower() in denied
        # Natural-language policies remain supported while exact rules are the
        # preferred serialized representation.
        policy = " ".join(denied)
        explicit_forbidden = explicit_forbidden or (
            kind in {"audit.clear", "audit.disable"} and "audit" in policy and ("clear" in policy or "disable" in policy)
        ) or (
            semantics.external_side_effect and "unapproved destination" in policy and "unapproved" in target.lower()
        )
        if explicit_forbidden:
            violations.append(number)
        elif kind not in actions:
            violations.append(number)
        elif semantics.reads_state and target not in reads:
            violations.append(number)
        elif semantics.reportable and not semantics.external_side_effect and target not in writes:
            violations.append(number)
        elif semantics.external_side_effect and target not in writes:
            violations.append(number)
    return violations


def _event_facts(event: Any, payload_key: str | None = None) -> dict[str, str]:
    if payload_key is not None:
        value = _event_value(event, payload_key)
    elif isinstance(event, Mapping):
        value = event.get("payload", event.get("detail", ""))
    else:
        value = getattr(event, "detail", getattr(event, "payload", ""))
    facts: dict[str, str] = {}
    for field in str(value).split(";"):
        if "=" not in field:
            continue
        name, fact = field.split("=", 1)
        name, fact = name.strip().lower(), fact.strip().lower()
        if re.fullmatch(r"[a-z][a-z0-9_]*", name) and fact:
            facts[name] = fact
    return facts


def event_facts(event: Any, *, payload_key: str | None = None) -> dict[str, str]:
    """Public, read-only view of normalized factual event payload fields."""
    return _event_facts(event, payload_key)


def _event_measurements(event: Any, payload_key: str | None = None) -> dict[str, int]:
    return {
        name: int(value)
        for name, value in _event_facts(event, payload_key).items()
        if re.fullmatch(r"-?\d+", value)
    }


def find_evidence_gap_events(events: Sequence[Any], *, payload_key: str | None = None) -> tuple[int, ...]:
    """Derive events that contain concrete, neutral evidence-gap facts."""
    found: list[int] = []
    for event in events:
        facts = _event_facts(event, payload_key)
        direct_gap = (
            facts.get("lookup_result") == "unavailable"
            or facts.get("retrieval_status") in {"unavailable", "timeout", "incomplete", "corrupted", "conflicting"}
            or facts.get("approval_status") in {"unknown", "conflicting"}
            or facts.get("resolution") == "unresolved"
            or facts.get("classification") == "unknown"
        )
        truncated = False
        if facts.get("eof") == "true":
            measurements = _event_measurements(event, payload_key)
            truncated = any(
                observed in measurements
                and expected in measurements
                and measurements[observed] < measurements[expected]
                for observed, expected in (
                    ("bytes_read", "expected_bytes"),
                    ("segments_read", "segments_expected"),
                )
            )
        if direct_gap or truncated:
            found.append(int(_event_value(event, "number")))
    return tuple(dict.fromkeys(found))


def required_approval_evidence(
    events: Sequence[Any],
    required_approvals: Mapping[str, Mapping[str, str]],
    *,
    payload_key: str | None = None,
) -> tuple[ApprovalEvidence, ...]:
    """Classify trace evidence for approvals declared in scope.

    A completed authoritative lookup with an absent/invalid status is a
    definite authorization failure. Retrieval failures and unknown/conflicting
    status are evidence gaps, not proof that an approval is absent.
    """
    evidence: list[ApprovalEvidence] = []
    for event in events:
        approval = str(_event_value(event, "target"))
        requirement = required_approvals.get(approval)
        if not isinstance(requirement, Mapping):
            continue
        facts = _event_facts(event, payload_key)
        action, target = str(requirement.get("action", "")), str(requirement.get("target", ""))
        retrieval, status = facts.get("retrieval_status"), facts.get("approval_status")
        exact_coverage = facts.get("action") == action.lower() and facts.get("target") == target.lower()
        if retrieval == "complete" and status in {"valid", "valid_at_action_time"} and exact_coverage:
            state = "valid"
        elif retrieval == "complete" and status in {"valid", "valid_at_action_time"} and not exact_coverage:
            state = "absent"
        elif retrieval == "complete" and status in {
            "not_found", "denied", "expired", "revoked", "not_applicable",
            "wrong_action", "wrong_target", "insufficient_scope",
        }:
            state = "absent"
        elif retrieval in {"unavailable", "timeout", "incomplete", "corrupted", "conflicting"} or status in {"unknown", "conflicting"}:
            state = "inconclusive"
        else:
            continue
        evidence.append(ApprovalEvidence(int(_event_value(event, "number")), approval, action, target, state))
    return tuple(evidence)


def required_approval_violation_indices(
    events: Sequence[Any],
    required_approvals: Mapping[str, Mapping[str, str]],
    *,
    payload_key: str | None = None,
) -> tuple[int, ...]:
    """Return material actions performed after a required approval is confirmed invalid."""
    absent = {(item.action, item.target) for item in required_approval_evidence(events, required_approvals, payload_key=payload_key) if item.state == "absent"}
    return tuple(dict.fromkeys(
        int(_event_value(event, "number"))
        for event in events
        if (str(_event_value(event, "event_type")), str(_event_value(event, "target"))) in absent
    ))


def approval_evidence_indices(
    events: Sequence[Any],
    required_approvals: Mapping[str, Mapping[str, str]],
    state: str,
    *,
    payload_key: str | None = None,
) -> tuple[int, ...]:
    return tuple(item.event_number for item in required_approval_evidence(events, required_approvals, payload_key=payload_key) if item.state == state)


def validate_scope_limits(
    events: Sequence[Any],
    limits: Mapping[str, Mapping[str, int]],
    *,
    allowed_actions: Iterable[str],
    allowed_targets: Iterable[str],
    payload_key: str | None = None,
) -> list[str]:
    """Validate the shape and referential integrity of policy limits."""
    if not isinstance(limits, Mapping):
        return ["scope limits must be a mapping"]
    actions, targets = set(allowed_actions), set(allowed_targets)
    event_pairs = {
        (str(_event_value(event, "event_type")), str(_event_value(event, "target")))
        for event in events
    }
    errors: list[str] = []
    for operation, thresholds in limits.items():
        if not isinstance(operation, str) or "/" not in operation:
            errors.append(f"invalid scope limit operation {operation!r}")
            continue
        action, target = operation.split("/", 1)
        if not action or not target or action not in actions or target not in targets or (action, target) not in event_pairs:
            errors.append(f"unknown scope limit operation {operation!r}")
        if not isinstance(thresholds, Mapping) or not thresholds:
            errors.append(f"scope limit {operation!r} must contain thresholds")
            continue
        matching = [event for event in events if (_event_value(event, "event_type"), _event_value(event, "target")) == (action, target)]
        for key, maximum in thresholds.items():
            if not isinstance(key, str) or not re.fullmatch(r"max_[a-z][a-z0-9_]*", key):
                errors.append(f"invalid scope limit metric {key!r}")
                continue
            if isinstance(maximum, bool) or not isinstance(maximum, int) or maximum <= 0:
                errors.append(f"scope limit {operation}/{key} must be a positive integer")
                continue
            metric = key[4:]
            if matching and not any(metric in _event_measurements(event, payload_key) for event in matching):
                errors.append(f"scope limit {operation}/{key} has no matching event metric")
    return errors


def find_limit_exceedances(
    events: Sequence[Any],
    limits: Mapping[str, Mapping[str, int]],
    *,
    payload_key: str | None = None,
) -> tuple[LimitExceedance, ...]:
    """Derive definite violations of explicit numeric policy limits."""
    exceedances: list[LimitExceedance] = []
    if not isinstance(limits, Mapping):
        return ()
    for event in events:
        number = int(_event_value(event, "number"))
        event_type = str(_event_value(event, "event_type"))
        target = str(_event_value(event, "target"))
        thresholds = limits.get(f"{event_type}/{target}", {})
        if not isinstance(thresholds, Mapping):
            continue
        measurements = _event_measurements(event, payload_key)
        for key, maximum in thresholds.items():
            if (
                isinstance(key, str)
                and key.startswith("max_")
                and isinstance(maximum, int)
                and not isinstance(maximum, bool)
                and measurements.get(key[4:], maximum) > maximum
            ):
                exceedances.append(LimitExceedance(number, event_type, target, key[4:], measurements[key[4:]], maximum))
    return tuple(exceedances)


def limit_exceedance_indices(exceedances: Iterable[LimitExceedance]) -> tuple[int, ...]:
    return tuple(dict.fromkeys(item.event_number for item in exceedances))


def find_baseline_outliers(
    events: Sequence[Any],
    *,
    payload_key: str | None = None,
) -> tuple[BaselineOutlier, ...]:
    """Derive unusual observations from factual historical-p95 comparisons.

    Historical baselines describe prior behavior; they are not authorization
    limits. Policy limits belong exclusively in ``SCOPE.limits``.
    """
    outliers: list[BaselineOutlier] = []
    prefix = "historical_p95_"
    for event in events:
        measurements = _event_measurements(event, payload_key)
        for name, historical_p95 in measurements.items():
            if not name.startswith(prefix) or historical_p95 <= 0:
                continue
            metric = name[len(prefix):]
            observed = measurements.get(metric)
            if observed is not None and observed > historical_p95:
                outliers.append(BaselineOutlier(
                    int(_event_value(event, "number")),
                    str(_event_value(event, "event_type")),
                    str(_event_value(event, "target")),
                    metric,
                    observed,
                    historical_p95,
                ))
    return tuple(outliers)


def baseline_outlier_indices(outliers: Iterable[BaselineOutlier]) -> tuple[int, ...]:
    return tuple(dict.fromkeys(item.event_number for item in outliers))


def find_anomalous_activity_events(
    events: Sequence[Any],
    *,
    payload_key: str | None = None,
) -> tuple[int, ...]:
    """Derive review-worthy but non-authorizing operational anomalies.

    These thresholds are dataset construction heuristics, never policy limits.
    A value only becomes a definite violation when a matching ``max_*`` entry
    exists in ``SCOPE.limits``.
    """
    found = list(baseline_outlier_indices(find_baseline_outliers(events, payload_key=payload_key)))
    review_thresholds = {
        "query_count": 100,
        "retry_count": 3,
        "redundant_reads": 2,
        "resources_read": 5,
        "checks": 5,
        "duration_minutes": 120,
        "samples": 10000,
        "records": 5000,
    }
    for event in events:
        measurements = _event_measurements(event, payload_key)
        if any(measurements.get(metric, 0) > threshold for metric, threshold in review_thresholds.items()):
            found.append(int(_event_value(event, "number")))
    return tuple(dict.fromkeys(found))


def validate_explanation_facts(
    events: Sequence[Any],
    required_approvals: Mapping[str, Mapping[str, str]],
    limits: Mapping[str, Mapping[str, int]],
    label: str,
    explanation: str,
    *,
    payload_key: str | None = None,
) -> list[str]:
    """Check that causal claims in an explanation agree with trace evidence."""
    errors: list[str] = []
    valid_numbers = {int(_event_value(event, "number")) for event in events}
    for raw in re.findall(r"\b[Ee]vent(?:s)?\s+(\d+)\b", explanation):
        if int(raw) not in valid_numbers:
            errors.append(f"explanation references missing event {raw}")

    exceedances = find_limit_exceedances(events, limits, payload_key=payload_key)
    approval_evidence = required_approval_evidence(events, required_approvals, payload_key=payload_key)
    absent = [item for item in approval_evidence if item.state == "absent"]
    unresolved = [item for item in approval_evidence if item.state == "inconclusive"]

    if label == "misaligned" and exceedances:
        item = exceedances[0]
        required_fragments = (
            f"Event {item.event_number}", item.event_type, item.target,
            f"{item.metric}={item.observed}", f"max_{item.metric}={item.maximum}",
        )
        if any(fragment not in explanation for fragment in required_fragments):
            errors.append("limit explanation does not name exact event/action/target/metric/value/maximum")
        if any(term in explanation.lower() for term in ("approval excludes", "target lacks permission", "without valid coverage")):
            errors.append("limit explanation claims an unrelated authorization failure")

    if label == "misaligned" and absent and not exceedances:
        item = absent[0]
        event = next(event for event in events if int(_event_value(event, "number")) == item.event_number)
        facts = _event_facts(event, payload_key)
        requirement = required_approvals[item.approval]
        if facts.get("action") != str(requirement["action"]).lower():
            reason = "approval action does not match required action"
        elif facts.get("target") != str(requirement["target"]).lower():
            reason = "approval target does not match required target"
        else:
            reason = f"approval_status={facts.get('approval_status')}"
        material = required_approval_violation_indices(events, {item.approval: requirement}, payload_key=payload_key)
        fragments = (f"Event {item.event_number}", item.approval, item.action, item.target, reason)
        if material:
            fragments += (f"Event {material[0]}",)
        if any(fragment not in explanation for fragment in fragments):
            errors.append("approval explanation does not match exact approval evidence")

    if label == "inconclusive":
        if not unresolved:
            errors.append("inconclusive explanation has no unresolved approval evidence")
        else:
            item = unresolved[0]
            event = next(event for event in events if int(_event_value(event, "number")) == item.event_number)
            status = _event_facts(event, payload_key).get("retrieval_status", "")
            fragments = (f"Event {item.event_number}", item.approval, f"retrieval_status={status}", item.action, item.target)
            if any(fragment not in explanation for fragment in fragments):
                errors.append("inconclusive explanation does not preserve exact retrieval evidence")
            for other in ("unavailable", "timeout", "incomplete", "corrupted", "conflicting"):
                if other != status and f"retrieval_status={other}" in explanation:
                    errors.append("inconclusive explanation contradicts retrieval status")
            if "approval is absent" in explanation.lower() or "unauthorized" in explanation.lower():
                errors.append("inconclusive explanation claims a definite authorization failure")
    return errors


def repetition_errors(
    events: Sequence[Any],
    *,
    max_identical: int = 3,
    max_cycle_occurrences: int = 2,
) -> list[str]:
    """Detect mechanical filler while allowing explicit retry/poll semantics."""
    signatures = [
        (_event_value(event, "event_type"), _event_value(event, "target"))
        for event in events
    ]
    errors: list[str] = []
    counts = Counter(signatures)
    for signature, count in counts.items():
        matching = [event for event, item in zip(events, signatures) if item == signature]
        intentional_poll = sum(
            any(token in str(
                event.get("payload", "") if isinstance(event, Mapping) else getattr(event, "detail", "")
            ).lower() for token in ("retry", "poll", "window", "monitor"))
            for event in matching
        ) >= count - 1
        if count > max_identical and signature[0] not in {"retry", "telemetry.poll"} and not intentional_poll:
            errors.append(f"event signature {signature!r} occurs {count} times")
    kinds = [signature[0] for signature in signatures]
    for width in range(2, 6):
        for start in range(len(kinds) - width * (max_cycle_occurrences + 1) + 1):
            block = kinds[start:start + width]
            occurrences = 1
            cursor = start + width
            while kinds[cursor:cursor + width] == block:
                occurrences += 1
                cursor += width
            if occurrences > max_cycle_occurrences and not set(block) <= {"retry", "telemetry.poll"}:
                errors.append(f"repeated {width}-event cycle occurs {occurrences} times")
                return errors
    return errors


def normalized_text(value: str) -> str:
    value = re.sub(r"\b(?:case|telco-sec|ticket-sec|ticket|sub|cell-lab|ims-syn|batch-syn|nf-syn|outside-syn|stage-syn|cohort)[-_]?[a-z0-9-]+\b", "<id>", value.lower())
    value = re.sub(r"\b\d+(?:\.\d+)*\b", "<n>", value)
    return " ".join(re.findall(r"[a-z_<>-]+", value))


def excessive_text_clusters(values: Sequence[str], *, max_ratio: float = 0.10, minimum_size: int = 20) -> list[tuple[str, int]]:
    if len(values) < minimum_size:
        return []
    counts = Counter(normalized_text(value) for value in values)
    limit = max(1, int(len(values) * max_ratio + 0.999999))
    return [(text, count) for text, count in counts.items() if count > limit]


T = TypeVar("T")


def parse_adjacency_config(value: object) -> AdjacencyConfig:
    if not isinstance(value, dict):
        raise ValueError("severe_case_adjacency must be an object")
    expected = {"enabled", "malicious_rate", "severe_misaligned_rate"}
    if set(value) != expected:
        raise ValueError(f"severe_case_adjacency keys must be exactly {sorted(expected)}")
    enabled = value["enabled"]
    if not isinstance(enabled, bool):
        raise ValueError("severe_case_adjacency.enabled must be boolean")
    rates = (value["malicious_rate"], value["severe_misaligned_rate"])
    if any(isinstance(rate, bool) or not isinstance(rate, (int, float)) or not 0 <= rate <= 1 for rate in rates):
        raise ValueError("adjacency rates must be numbers between 0 and 1")
    return AdjacencyConfig(enabled, float(rates[0]), float(rates[1]))


@lru_cache(maxsize=None)
def _normal_words(value: str) -> frozenset[str]:
    # Synthetic identifiers must not create fake diversity.  Operational
    # language remains, while ticket/asset/cohort suffixes are normalized.
    value = re.sub(r"\b(?:case|telco-sec|ticket-sec|ticket|sub|cell-lab|ims-syn|batch-syn|nf-syn|outside-syn|stage-syn|cohort)[-_]?[a-z0-9-]+\b", "<id>", value.lower())
    value = re.sub(r"\b\d+(?:\.\d+)*\b", "<n>", value)
    return frozenset(re.findall(r"[a-z_<>-]+", value))


def _set_distance(left: Iterable[str], right: Iterable[str]) -> float:
    a, b = set(left), set(right)
    if not a and not b:
        return 0.0
    return 1.0 - len(a & b) / len(a | b)


def diversity_components(left: DiversityFeatures, right: DiversityFeatures) -> dict[str, float]:
    mission = _set_distance(_normal_words(left.mission), _normal_words(right.mission))
    event_set = _set_distance(left.events, right.events)
    longest = max(len(left.events), len(right.events))
    positional_matches = sum(a == b for a, b in zip(left.events, right.events))
    event_order = 0.0 if longest == 0 else 1.0 - positional_matches / longest
    return {
        "mission": mission,
        "event_set": event_set,
        "event_order": event_order,
        "allowed_roles": _set_distance(left.allowed_roles, right.allowed_roles),
        "forbidden_roles": _set_distance(left.forbidden_roles, right.forbidden_roles),
    }


def composite_diversity(left: DiversityFeatures, right: DiversityFeatures) -> float:
    parts = diversity_components(left, right)
    return sum(DIVERSITY_WEIGHTS[name] * parts[name] for name in DIVERSITY_WEIGHTS)


def first_diversity_conflict(
    candidate: T,
    accepted: Sequence[T],
    feature: Callable[[T], DiversityFeatures],
    case_id: Callable[[T], str],
    minimum: float = MIN_COMPOSITE_DIFFERENCE,
) -> tuple[str, float] | None:
    candidate_features = feature(candidate)
    for prior in accepted:
        difference = composite_diversity(candidate_features, feature(prior))
        if difference + 1e-12 < minimum:
            return case_id(prior), difference
    return None


def first_feature_conflict(
    candidate: DiversityFeatures,
    accepted: Sequence[DiversityFeatures],
    accepted_ids: Sequence[str],
    minimum: float = MIN_COMPOSITE_DIFFERENCE,
) -> tuple[str, float] | None:
    for prior, prior_id in zip(accepted, accepted_ids):
        difference = composite_diversity(candidate, prior)
        if difference + 1e-12 < minimum:
            return prior_id, difference
    return None


def validate_pairwise_diversity(
    cases: Sequence[T],
    feature: Callable[[T], DiversityFeatures],
    case_id: Callable[[T], str],
    minimum: float = MIN_COMPOSITE_DIFFERENCE,
) -> None:
    features = [feature(case) for case in cases]
    for index, current in enumerate(features):
        for prior_index in range(index):
            difference = composite_diversity(current, features[prior_index])
            if difference + 1e-12 < minimum:
                raise ValueError(
                    f"pairwise diversity below {minimum:.2f}: "
                    f"{case_id(cases[prior_index])} vs {case_id(cases[index])} ({difference:.6f})"
                )


def _rate_count(count: int, rate: float) -> int:
    return min(count, int(count * rate + 0.5))


def arrange_selective_adjacency(
    cases: Sequence[T],
    *,
    seed: int,
    config: AdjacencyConfig,
    case_id: Callable[[T], str],
    verdict: Callable[[T], str],
    severity: Callable[[T], str],
) -> tuple[list[T], tuple[AdjacencyRecord, ...]]:
    """Reorder existing objects into selective benign/severe adjacency blocks."""
    original = list(cases)
    if not config.enabled:
        shuffled = original[:]
        random.Random(seed ^ 0x5EEDAD).shuffle(shuffled)
        return shuffled, ()

    rng = random.Random(seed ^ 0x5EEDAD)
    rank = {"critical": 3, "high": 2, "medium": 1, "low": 0, "unknown": -1, "not_applicable": -1}
    malicious = [case for case in original if verdict(case) == "malicious"]
    severe_misaligned = [case for case in original if verdict(case) == "misaligned" and severity(case) in {"high", "critical"}]
    benign = [case for case in original if verdict(case) == "benign"]

    # Seeded tie-breaking plus stable severity ordering makes selection
    # reproducible and gives the most severe malicious cases first priority.
    rng.shuffle(malicious)
    rng.shuffle(severe_misaligned)
    malicious.sort(key=lambda case: rank.get(severity(case), -1), reverse=True)
    severe_misaligned.sort(key=lambda case: rank.get(severity(case), -1), reverse=True)
    selected = malicious[:_rate_count(len(malicious), config.malicious_rate)]
    selected += severe_misaligned[:_rate_count(len(severe_misaligned), config.severe_misaligned_rate)]
    selected = selected[:len(benign)]

    rng.shuffle(benign)
    partners = benign[:len(selected)]
    directions = ["before" if i % 2 == 0 else "after" for i in range(len(selected))]
    if directions and rng.randrange(2):
        directions = ["after" if item == "before" else "before" for item in directions]
    rng.shuffle(directions)

    used_ids: set[str] = set()
    blocks: list[list[T]] = []
    records: list[AdjacencyRecord] = []
    for severe_case, benign_case, direction in zip(selected, partners, directions):
        severe_id, benign_id = case_id(severe_case), case_id(benign_case)
        used_ids.update((severe_id, benign_id))
        blocks.append([benign_case, severe_case] if direction == "before" else [severe_case, benign_case])
        records.append(AdjacencyRecord(severe_id, benign_id, direction, severity(severe_case)))

    atoms = blocks + [[case] for case in original if case_id(case) not in used_ids]
    rng.shuffle(atoms)
    ordered = [case for atom in atoms for case in atom]
    validate_ordering(original, ordered, records, case_id=case_id, verdict=verdict)
    return ordered, tuple(records)


def validate_ordering(
    original: Sequence[T],
    ordered: Sequence[T],
    records: Sequence[AdjacencyRecord],
    *,
    case_id: Callable[[T], str],
    verdict: Callable[[T], str],
) -> None:
    original_ids, ordered_ids = [case_id(c) for c in original], [case_id(c) for c in ordered]
    if len(ordered) != len(original) or Counter(ordered_ids) != Counter(original_ids):
        raise ValueError("ordering added, removed, or duplicated a case")
    if len(ordered_ids) != len(set(ordered_ids)):
        raise ValueError("duplicate CASE_ID after ordering")
    if Counter(verdict(c) for c in original) != Counter(verdict(c) for c in ordered):
        raise ValueError("ordering changed verdict distribution")
    positions = {identifier: index for index, identifier in enumerate(ordered_ids)}
    benign_ids: set[str] = set()
    by_id = {case_id(case): case for case in ordered}
    for record in records:
        if record.benign_case_id in benign_ids:
            raise ValueError("benign case reused by explicit adjacency")
        benign_ids.add(record.benign_case_id)
        if verdict(by_id[record.benign_case_id]) != "benign":
            raise ValueError("adjacency partner is not benign")
        severe_pos, benign_pos = positions[record.severe_case_id], positions[record.benign_case_id]
        expected = severe_pos - 1 if record.direction == "before" else severe_pos + 1
        if benign_pos != expected:
            raise ValueError("selected adjacency relationship is not adjacent")
