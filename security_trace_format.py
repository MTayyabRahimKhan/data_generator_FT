"""Exact public text format and cross-domain dataset validation."""
from __future__ import annotations

import re
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from typing import Any, Iterable, Mapping, Sequence

from security_trace_core import (
    find_evidence_gap_events, find_limit_exceedances, limit_exceedance_indices,
    validate_scope_limits,
)


LABELS = frozenset({"benign", "suspicious", "misaligned", "malicious", "inconclusive"})
TWIN_REQUIRED = frozenset({"suspicious", "misaligned", "malicious"})
LEAKAGE_PATTERNS = (
    r"\b(?:un)?authori[sz]ed\b",
    r"\bexplicitly\s+authori[sz]ed\b",
    r"\bapproved\b",
    r"\bunapproved\b",
    r"\bforbidden\b",
    r"\bmalicious\b",
    r"\bsuspicious\b",
    r"\bout[_ -]?of[_ -]?scope\b",
    r"\bwrong[_ -](?:target|subscriber|slice|cell|partner|network)\b",
    r"\btarget omitted from approval\b",
    r"\bclear evidence of\b",
    r"\bweaken(?:ed|ing)?\s+(?:a\s+)?protected\b",
    r"\bprotected[_ -]",
    r"\bscope violation\b",
    r"\boutside (?:the )?(?:request|ticket|scope)\b",
)
LEAKAGE_RE = re.compile("|".join(f"(?:{pattern})" for pattern in LEAKAGE_PATTERNS), re.IGNORECASE)
EVENT_RE = re.compile(r"^  (?P<number>\d+)  (?P<kind>\S+)(?:  (?P<target>\S+))?(?:  (?P<payload>.*))?$")
FAMILY_RE = re.compile(r"^(?:DB|TELCO)-FAMILY-\d{6}$")


def largest_remainder(total: int, weights: Mapping[str, int | float], order: Sequence[str]) -> dict[str, int]:
    if total < 0:
        raise ValueError("allocation total cannot be negative")
    denominator=sum(weights[name] for name in order)
    if denominator <= 0:
        if total:
            raise ValueError("positive allocation requires positive weights")
        return {name:0 for name in order}
    quotas={name:total*weights[name]/denominator for name in order}
    result={name:int(quotas[name]) for name in order}
    ranked=sorted(order,key=lambda name:(-(quotas[name]-result[name]),order.index(name)))
    for name in ranked[:total-sum(result.values())]:result[name]+=1
    return result


def plan_source_labels(final_total: int, percentages: Mapping[str, int | float], order: Sequence[str]) -> dict[str, Any]:
    """Allocate source labels while counting mandatory twins inside final_total."""
    if final_total < 1:
        raise ValueError("--cases must be a positive integer")
    standalone=[name for name in order if name not in TWIN_REQUIRED]
    severe=[name for name in order if name in TWIN_REQUIRED]
    best=None
    for source_total in range((final_total+1)//2,final_total+1):
        twin_total=final_total-source_total
        if twin_total>source_total:continue
        standalone_total=source_total-twin_total
        severe_counts=largest_remainder(twin_total,percentages,severe)
        standalone_counts=largest_remainder(standalone_total,percentages,standalone)
        counts={name:severe_counts.get(name,standalone_counts.get(name,0)) for name in order}
        error=sum(abs(counts[name]-source_total*percentages[name]/sum(percentages.values())) for name in order)
        candidate=(round(error,12),-source_total,counts,source_total,twin_total)
        if best is None or candidate[:2]<best[:2]:best=candidate
    _,_,counts,source_total,twin_total=best
    final_labels=dict(counts);final_labels["benign"]+=twin_total
    return {"source_labels":counts,"source_count":source_total,"twin_count":twin_total,"final_labels":final_labels,"final_count":final_total}


def _csv(values: Iterable[str]) -> str:
    return ", ".join(str(value) for value in values)


def _changed_text(values: Sequence[str]) -> str:
    return "; ".join(str(value) for value in values) if values else "none"


def _contributors_text(values: Sequence[int]) -> str:
    return "[" + ", ".join(str(value) for value in values) + "]"


def _render_limits(limits: Mapping[str, Mapping[str, int]]) -> list[str]:
    if not limits:
        return ["  limits: {}"]
    lines = ["  limits:"]
    for operation, thresholds in limits.items():
        lines.append(f"    {operation}:")
        lines.extend(f"      {name}: {value}" for name, value in thresholds.items())
    return lines


def render_item(item: Mapping[str, Any], action_key: str, payload_key: str) -> str:
    scope = item["SCOPE"]
    output = item["OUTPUT"]
    lines = [
        f"family_id: {item['family_id']}",
        f"MISSION: {item['MISSION']}",
        "SCOPE:",
        f"  allowed reads: {_csv(scope['allowed reads'])}",
        f"  allowed writes: {_csv(scope['allowed writes'])}",
        f"  {action_key}: {_csv(scope[action_key])}",
    ]
    lines.extend(_render_limits(scope["limits"]))
    lines.extend((f"  forbidden: {_csv(scope['forbidden'])}", "EVENTS:"))
    for event in item["EVENTS"]:
        parts = [f"  {event['number']}", event["event_type"]]
        if event.get("target"):
            parts.append(str(event["target"]))
        if event.get(payload_key):
            parts.append(str(event[payload_key]))
        lines.append("  ".join(parts))
    lines.extend((
        "OUTPUT:",
        f"  changed: {_changed_text(output['changed'])}",
        f"  authorised: {output['authorised']}",
        f"  first_deviation: {output['first_deviation']}",
        f"  contributing_events: {_contributors_text(output['contributing_events'])}",
        f"  label: {output['label']}",
        f"  explanation: {output['explanation']}",
    ))
    return "\n".join(lines)


def serialize_items(items: Sequence[Mapping[str, Any]], action_key: str, payload_key: str) -> str:
    return "\n---\n".join(render_item(item, action_key, payload_key) for item in items) + "\n"


def mission_similarity(left: str, right: str) -> float:
    normalize = lambda value: re.sub(r"\s+", " ", value.strip().lower())
    left_normalized,right_normalized=normalize(left),normalize(right)
    left_tokens=set(re.findall(r"[a-z0-9]+",left_normalized));right_tokens=set(re.findall(r"[a-z0-9]+",right_normalized))
    token_jaccard=len(left_tokens&right_tokens)/max(1,len(left_tokens|right_tokens))
    # A 90% character match necessarily has substantial lexical overlap. This
    # inexpensive gate avoids quadratic SequenceMatcher work for clearly
    # unrelated missions while retaining the strict check for close pairs.
    if token_jaccard < .70:return token_jaccard
    return SequenceMatcher(None,left_normalized,right_normalized).ratio()


def validate_mission_similarity(items: Sequence[Mapping[str, Any]], maximum: float = 0.90) -> None:
    representatives: list[tuple[str, str]] = []
    seen: set[str] = set()
    for item in items:
        family = item["family_id"]
        if family not in seen:
            seen.add(family)
            representatives.append((family, item["MISSION"]))
    for index, (family, mission) in enumerate(representatives):
        for prior_family, prior_mission in representatives[:index]:
            score = mission_similarity(mission, prior_mission)
            if score > maximum + 1e-12:
                raise ValueError(
                    f"mission similarity {score:.3%} exceeds {maximum:.0%}: "
                    f"{prior_family} and {family}"
                )


def leakage_matches(text: str) -> list[str]:
    return [match.group(0) for match in LEAKAGE_RE.finditer(text)]


def validate_no_label_leakage(mission: str, events: Sequence[Mapping[str, Any]], payload_key: str) -> None:
    observed = [mission]
    for event in events:
        observed.extend((str(event.get("event_type", "")), str(event.get("target", "")), str(event.get(payload_key, ""))))
    matches = leakage_matches("\n".join(observed))
    if matches:
        raise ValueError(f"answer-bearing event or mission text: {matches[0]!r}")


def _parse_document(document: str, action_key: str) -> dict[str, Any]:
    lines = document.splitlines()
    if len(lines) < 17:
        raise ValueError("serialized item is incomplete")
    fixed = (
        (0, "family_id: "), (1, "MISSION: "), (2, "SCOPE:"),
        (3, "  allowed reads: "), (4, "  allowed writes: "),
        (5, f"  {action_key}: "),
    )
    for index, prefix in fixed:
        if lines[index] != prefix.rstrip() and not lines[index].startswith(prefix):
            raise ValueError(f"serialized key/order mismatch at line {index + 1}: {lines[index]!r}")
    cursor = 6
    limits: dict[str, dict[str, int]] = {}
    if lines[cursor] == "  limits: {}":
        cursor += 1
    elif lines[cursor] == "  limits:":
        cursor += 1
        while cursor < len(lines) and lines[cursor].startswith("    "):
            operation_line = lines[cursor]
            if not operation_line.startswith("    ") or operation_line.startswith("      ") or not operation_line.endswith(":"):
                raise ValueError(f"invalid serialized limit operation: {operation_line!r}")
            operation = operation_line[4:-1]
            if operation in limits:
                raise ValueError(f"duplicate serialized limit operation: {operation!r}")
            cursor += 1
            thresholds: dict[str, int] = {}
            while cursor < len(lines) and lines[cursor].startswith("      "):
                threshold_line = lines[cursor][6:]
                if ": " not in threshold_line:
                    raise ValueError(f"invalid serialized limit threshold: {lines[cursor]!r}")
                name, raw_value = threshold_line.split(": ", 1)
                if name in thresholds or not re.fullmatch(r"-?\d+", raw_value):
                    raise ValueError(f"invalid serialized limit threshold: {lines[cursor]!r}")
                thresholds[name] = int(raw_value)
                cursor += 1
            if not thresholds:
                raise ValueError(f"serialized limit operation has no thresholds: {operation!r}")
            limits[operation] = thresholds
    else:
        raise ValueError("serialized SCOPE must contain limits")
    if cursor >= len(lines) or not lines[cursor].startswith("  forbidden: "):
        raise ValueError("serialized SCOPE must contain forbidden after limits")
    forbidden_line = lines[cursor]
    cursor += 1
    if cursor >= len(lines) or lines[cursor] != "EVENTS:":
        raise ValueError("serialized SCOPE must be followed by EVENTS")
    events_index = cursor
    try:
        output_index = lines.index("OUTPUT:", events_index + 1)
    except ValueError as exc:
        raise ValueError("missing OUTPUT section") from exc
    event_lines = lines[events_index + 1:output_index]
    events = []
    for expected, line in enumerate(event_lines, 1):
        match = EVENT_RE.fullmatch(line)
        if not match or int(match.group("number")) != expected:
            raise ValueError(f"invalid event line: {line!r}")
        events.append(match.groupdict())
    output_prefixes = (
        "  changed: ", "  authorised: ", "  first_deviation: ",
        "  contributing_events: ", "  label: ", "  explanation: ",
    )
    output_lines = lines[output_index + 1:]
    if len(output_lines) != len(output_prefixes):
        raise ValueError("OUTPUT must contain exactly six keys")
    values = {}
    for line, prefix in zip(output_lines, output_prefixes):
        if not line.startswith(prefix):
            raise ValueError(f"serialized OUTPUT key/order mismatch: {line!r}")
        values[prefix.strip()[:-1]] = line[len(prefix):]
    family = lines[0].split(": ", 1)[1]
    if not FAMILY_RE.fullmatch(family):
        raise ValueError(f"invalid family_id: {family!r}")
    label = values["label"]
    if label not in LABELS:
        raise ValueError(f"invalid label: {label!r}")
    if values["authorised"] not in {"yes", "no", "undetermined"}:
        raise ValueError("invalid authorised value")
    event_text = "\n".join(event_lines)
    matches = leakage_matches(lines[1][len("MISSION: "):] + "\n" + event_text)
    if matches:
        raise ValueError(f"serialized answer-bearing text: {matches[0]!r}")
    forbidden = forbidden_line[len("  forbidden: "):]
    return {
        "family_id": family,
        "mission": lines[1][len("MISSION: "):],
        "events": events,
        "event_lines": event_lines,
        "allowed_reads": tuple(part.strip() for part in lines[3][len("  allowed reads: "):].split(",") if part.strip()),
        "allowed_writes": tuple(part.strip() for part in lines[4][len("  allowed writes: "):].split(",") if part.strip()),
        "allowed_actions": tuple(part.strip() for part in lines[5][len(f"  {action_key}: "):].split(",") if part.strip()),
        "limits": limits,
        "forbidden": tuple(part.strip() for part in forbidden.split(",") if part.strip()),
        **values,
    }


def _parsed_contributors(value: str) -> tuple[int, ...]:
    if not re.fullmatch(r"\[(?:\d+(?:, \d+)*)?\]", value):
        raise ValueError(f"invalid contributing_events value: {value!r}")
    return tuple(int(part) for part in value[1:-1].split(", ") if part)


def validate_serialized_dataset(
    text: str,
    action_key: str,
    expected_total_count: int | None = None,
    mission_similarity_limit: float = 0.90,
) -> list[dict[str, Any]]:
    if not text.endswith("\n"):
        raise ValueError("serialized dataset must end with a newline")
    documents = [_parse_document(document, action_key) for document in text.rstrip("\n").split("\n---\n")]
    families: dict[str, list[dict[str, Any]]] = defaultdict(list)
    for document in documents:
        families[document["family_id"]].append(document)
    if expected_total_count is not None and len(documents) != expected_total_count:
        raise ValueError(f"serialized item count is {len(documents)}, expected {expected_total_count}")
    for family, members in families.items():
        labels = [member["label"] for member in members]
        source_labels = [label for label in labels if label in TWIN_REQUIRED]
        if source_labels:
            if len(members) != 2 or len(source_labels) != 1 or labels.count("benign") != 1:
                raise ValueError(f"{family} does not contain one source and one benign twin")
            if members[0]["label"] == "benign":
                raise ValueError(f"{family} benign twin must follow its source")
            if members[0]["mission"] != members[1]["mission"]:
                raise ValueError(f"{family} twin mission differs")
            if members[0]["limits"] != members[1]["limits"]:
                raise ValueError(f"{family} twin limits differ")
            left = [(event["kind"], event["target"]) for event in members[0]["events"]]
            right = [(event["kind"], event["target"]) for event in members[1]["events"]]
            if left != right:
                raise ValueError(f"{family} twin event shape differs")
            if members[1]["authorised"] != "yes" or members[1]["first_deviation"] != "none" or members[1]["contributing_events"] != "[]":
                raise ValueError(f"{family} has invalid benign twin output")
        elif len(members) != 1 or labels[0] not in {"benign", "inconclusive"}:
            raise ValueError(f"{family} has invalid standalone membership")

    for members in families.values():
        for member in members:
            events = [
                {"number": int(event["number"]), "event_type": event["kind"], "target": event["target"] or "", "payload": event["payload"] or ""}
                for event in member["events"]
            ]
            limit_errors = validate_scope_limits(
                events,
                member["limits"],
                allowed_actions=member["allowed_actions"],
                allowed_targets=(*member["allowed_reads"], *member["allowed_writes"]),
                payload_key="payload",
            )
            if limit_errors:
                raise ValueError(limit_errors[0])
            exceedances = find_limit_exceedances(events, member["limits"], payload_key="payload")
            gap_events = find_evidence_gap_events(events, payload_key="payload")
            contributors = _parsed_contributors(member["contributing_events"])
            if member["label"] == "suspicious":
                expected = limit_exceedance_indices(exceedances)
                if not member["limits"] or not expected or contributors != expected:
                    raise ValueError(f"{member['family_id']} suspicious contributors do not match scope-limit evidence")
                if member["authorised"] != "yes" or member["first_deviation"] != "none":
                    raise ValueError(f"{member['family_id']} has invalid suspicious authorization semantics")
            elif exceedances:
                raise ValueError(f"{member['family_id']} non-suspicious item has threshold evidence")
            if member["label"] == "inconclusive":
                if not gap_events or contributors != gap_events:
                    raise ValueError(f"{member['family_id']} inconclusive contributors do not match evidence-gap events")
                if member["authorised"] != "undetermined" or member["first_deviation"] != "none":
                    raise ValueError(f"{member['family_id']} has invalid inconclusive authorization semantics")
            elif gap_events:
                raise ValueError(f"{member['family_id']} non-inconclusive item has evidence-gap facts")
            if member["label"] == "benign" and contributors:
                raise ValueError(f"{member['family_id']} benign item has contributing events")

    representatives = [members[0] for members in families.values()]
    validate_mission_similarity(
        [{"family_id": member["family_id"], "MISSION": member["mission"]} for member in representatives],
        mission_similarity_limit,
    )
    profiles = Counter(member["forbidden"] for member in representatives)
    if len(representatives) >= 10 and len(profiles) < 3:
        raise ValueError("fewer than three forbidden-rule profiles")
    if len(representatives) >= 20 and max(profiles.values()) / len(representatives) > 0.40 + 1e-12:
        raise ValueError("one forbidden-rule profile exceeds 40%")

    definite = [member for member in representatives if member["label"] in {"misaligned", "malicious"}]
    buckets = Counter()
    for member in definite:
        deviation = int(member["first_deviation"].split()[1])
        ratio = (deviation - 2) / max(1, len(member["events"]) - 3)
        buckets["early" if ratio <= 1 / 3 else "middle" if ratio <= 2 / 3 else "late"] += 1
    if len(definite) >= 4:
        if any(buckets[name] / len(definite) < 0.25 - 1e-12 for name in ("early", "middle", "late")):
            raise ValueError(f"deviation position distribution is unbalanced: {dict(buckets)}")
        if buckets["late"] / len(definite) > 0.50 + 1e-12:
            raise ValueError("more than 50% of deviations occur in the final third")
    return documents
