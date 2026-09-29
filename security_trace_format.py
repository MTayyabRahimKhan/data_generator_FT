"""Exact public text format and cross-domain dataset validation."""
from __future__ import annotations

import re
import math
from collections import Counter, defaultdict
from difflib import SequenceMatcher
from typing import Any, Iterable, Mapping, Sequence

from security_trace_core import (
    approval_evidence_indices,
    baseline_outlier_indices, duplicate_event_attribute_errors, find_anomalous_activity_events, find_baseline_outliers, find_evidence_gap_events,
    find_limit_exceedances, limit_exceedance_indices, validate_scope_limits,
    required_approval_evidence, required_approval_violation_indices, validate_explanation_facts,
)


LABELS = frozenset({"benign", "suspicious", "misaligned", "malicious", "inconclusive"})
TWIN_ELIGIBLE = frozenset({"suspicious", "misaligned", "malicious"})
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
TEMPLATE_FAMILY_RE = re.compile(r"^TEMPLATE-FAMILY-\d{6}$")
SIMILARITY_HARD_CAP = 0.80


def normalize_similarity_text(value: str) -> str:
    """Normalize synthetic identity while retaining security semantics."""
    value=value.lower()
    replacements=(
        (r"\b(?:db|telco)-family-\d+\b","family_id"),
        (r"\btemplate-family-\d+\b","template_id"),
        (r"\bticket-sec-\d+\b","ticket_id"),
        (r"\bcell-lab-\d+\b","cell_id"),
        (r"\bsub-\d+\b","subscriber_id"),
        (r"\bnf-syn-\d+\b","network_function_id"),
        (r"\bbatch-syn-\d+\b","batch_id"),
        (r"\bims-syn-\d+\b","ims_id"),
        (r"\b(?:peer|stage|outside)-syn-\d+\b","synthetic_id"),
        (r"\bcase-\d+(?:-twin)?\b","case_id"),
        (r"\b(?:ops-syn|service_batch|handset)[-_]?\d+\b","principal_id"),
        (r"\b\d{4}-\d{2}-\d{2}(?:t\d{2}:\d{2}(?::\d{2})?z?)?\b","timestamp"),
    )
    for pattern,replacement in replacements:value=re.sub(pattern,replacement,value)
    return " ".join(re.findall(r"[a-z][a-z0-9_.<>/-]*|\d+",value))


def _cosine_tokens(left: str,right: str) -> float:
    a=Counter(normalize_similarity_text(left).split());b=Counter(normalize_similarity_text(right).split())
    return _cosine_counters(a,b)


def _cosine_counters(a: Counter,b: Counter) -> float:
    if not a and not b:return 1.0
    if not a or not b:return 0.0
    dot=sum(count*b.get(token,0) for token,count in a.items())
    return dot/(math.sqrt(sum(value*value for value in a.values()))*math.sqrt(sum(value*value for value in b.values())))


def _jaccard(left: Iterable[str],right: Iterable[str]) -> float:
    a,b=set(left),set(right)
    return 1.0 if not a and not b else len(a&b)/len(a|b)


def _action_scope_key(item: Mapping[str,Any]) -> str:
    return next(key for key in item["SCOPE"] if key.startswith("allowed ") and key.endswith(" actions"))


def _payload_key(item: Mapping[str,Any]) -> str:
    return "detail" if any("detail" in event for event in item["EVENTS"]) else "payload"


def _normalized_target(value: str) -> str:
    return normalize_similarity_text(value).replace("subscriber_id","<id>").replace("cell_id","<id>").replace("network_function_id","<id>").replace("batch_id","<id>").replace("ims_id","<id>").replace("synthetic_id","<id>")


def record_similarity(left: Mapping[str,Any],right: Mapping[str,Any]) -> float:
    """Composite similarity over substantive fields; IDs and labels are excluded."""
    return _record_similarity_features(_similarity_features(left),_similarity_features(right))


def _similarity_features(item: Mapping[str,Any]) -> dict[str,Any]:
    def scope_tokens():
        scope=item["SCOPE"];action_key=_action_scope_key(item);tokens=[]
        for key in ("allowed reads","allowed writes",action_key,"forbidden"):
            tokens.extend(f"{key}:{normalize_similarity_text(str(value))}" for value in scope.get(key,[]))
        for approval,requirement in scope.get("required approvals",{}).items():
            tokens.append(f"approval:{normalize_similarity_text(approval)}:{requirement.get('action')}:{_normalized_target(str(requirement.get('target','')))}")
        for operation,thresholds in scope.get("limits",{}).items():
            tokens.extend(f"limit:{_normalized_target(operation)}:{name}:{value}" for name,value in thresholds.items())
        return tokens
    event_structure=[f"{event['event_type']}:{_normalized_target(str(event.get('target','')))}" for event in item["EVENTS"]]
    payload_key=_payload_key(item)
    output=item["OUTPUT"]
    output_text=" ".join((str(output.get("authorised","")),str(output.get("first_deviation","")),str(len(output.get("contributing_events",[])))," ".join(map(str,output.get("changed",[]))),str(output.get("explanation",""))))
    scope=item["SCOPE"];action_key=_action_scope_key(item)
    parts=[str(item["MISSION"]),repr({key:scope.get(key) for key in ("allowed reads","allowed writes",action_key,"required approvals","limits","forbidden")})]
    parts.extend(f"{event['event_type']} {event.get('target','')} {event.get(payload_key,'')}" for event in item["EVENTS"])
    parts.extend((str(output.get("authorised","")),str(output.get("first_deviation","")),str(output.get("contributing_events",[])),str(output.get("changed",[])),str(output.get("explanation",""))))
    full_tokens=normalize_similarity_text(" ".join(parts)).split()
    return {
        "mission":Counter(normalize_similarity_text(str(item["MISSION"])).split()),
        "scope":set(scope_tokens()),"events":event_structure,
        "details":Counter(normalize_similarity_text(" ".join(str(event.get(payload_key,"")) for event in item["EVENTS"])).split()),
        "output":Counter(normalize_similarity_text(output_text).split()),
        "full":Counter(zip(full_tokens,full_tokens[1:])),
    }


def _record_similarity_features(left: Mapping[str,Any],right: Mapping[str,Any]) -> float:
    mission=_cosine_counters(left["mission"],right["mission"])
    scope=_jaccard(left["scope"],right["scope"])
    ls,rs=left["events"],right["events"]
    sequence=SequenceMatcher(None,ls,rs).ratio()
    count_ratio=min(len(ls),len(rs))/max(len(ls),len(rs)) if ls or rs else 1.0
    event_structure_similarity=.85*sequence+.15*count_ratio
    event_detail=_cosine_counters(left["details"],right["details"])
    output=_cosine_counters(left["output"],right["output"])
    return .20*mission+.20*scope+.30*event_structure_similarity+.15*event_detail+.15*output


def build_similarity_features(item: Mapping[str,Any]) -> dict[str,Any]:
    return _similarity_features(item)


def feature_similarity(left: Mapping[str,Any],right: Mapping[str,Any]) -> tuple[float,float]:
    return _record_similarity_features(left,right),_cosine_counters(left["full"],right["full"])


def normalized_full_record_similarity(left: Mapping[str,Any],right: Mapping[str,Any]) -> float:
    """Independent bigram-cosine safety check over the normalized record."""
    return _cosine_counters(_similarity_features(left)["full"],_similarity_features(right)["full"])


def global_similarity_audit(items: Sequence[Mapping[str,Any]],cap: float = SIMILARITY_HARD_CAP) -> dict[str,Any]:
    maximum=0.0;maximum_full=0.0;pair=None;full_pair=None;above=0
    features=[_similarity_features(item) for item in items]
    for index,current in enumerate(items):
        for prior_index in range(index):
            prior=items[prior_index];score=_record_similarity_features(features[prior_index],features[index]);full=_cosine_counters(features[prior_index]["full"],features[index]["full"])
            ids=(prior.get("family_id",prior_index),current.get("family_id",index))
            if score>maximum:maximum,pair=score,ids
            if full>maximum_full:maximum_full,full_pair=full,ids
            if score>cap+1e-12 or full>cap+1e-12:above+=1
    return {"maximum_pair_similarity":maximum,"maximum_pair":pair,"maximum_full_text_similarity":maximum_full,"maximum_full_text_pair":full_pair,"pairs_above_0.80":above}


def validate_global_similarity(items: Sequence[Mapping[str,Any]],cap: float = SIMILARITY_HARD_CAP) -> dict[str,Any]:
    audit=global_similarity_audit(items,cap)
    if audit["pairs_above_0.80"]:
        raise ValueError(f"{audit['pairs_above_0.80']} record pairs exceed similarity cap {cap:.2f}; maximum composite={audit['maximum_pair_similarity']:.6f} {audit['maximum_pair']}; maximum full-text={audit['maximum_full_text_similarity']:.6f} {audit['maximum_full_text_pair']}")
    return audit


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
    """Allocate the *final* labels, then reserve a selective set of benign twins.

    Twins consume the benign quota.  They are deliberately only a sample of
    eligible non-benign records, so family membership cannot reveal a verdict.
    """
    if final_total < 1:
        raise ValueError("--cases must be a positive integer")
    final_labels = largest_remainder(final_total, percentages, order)
    eligible_total = sum(final_labels.get(name, 0) for name in TWIN_ELIGIBLE)
    # Roughly one fifth of final items are contrasts, subject to the available
    # benign quota.  For useful-sized datasets include each eligible label.
    desired = min(final_labels.get("benign", 0), eligible_total, max(0, round(final_total * .20)))
    if final_total >= 10:
        desired = min(final_labels.get("benign", 0), eligible_total, max(desired, 1))
    eligible_order = [name for name in order if name in TWIN_ELIGIBLE]
    twin_sources = largest_remainder(
        desired,
        {name: final_labels[name] for name in eligible_order},
        eligible_order,
    ) if desired else {name: 0 for name in eligible_order}
    source_labels = dict(final_labels)
    source_labels["benign"] -= desired
    return {
        "source_labels": source_labels,
        "source_count": final_total - desired,
        "twin_count": desired,
        "twin_sources": twin_sources,
        "final_labels": final_labels,
        "final_count": final_total,
    }


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


def _render_required_approvals(required: Mapping[str, Mapping[str, str]]) -> list[str]:
    if not required:
        return ["  required approvals: {}"]
    lines = ["  required approvals:"]
    for approval, requirement in required.items():
        lines.append(f"    {approval}: action={requirement['action']};target={requirement['target']}")
    return lines


def render_item(item: Mapping[str, Any], action_key: str, payload_key: str) -> str:
    scope = item["SCOPE"]
    output = item["OUTPUT"]
    lines = [
        f"family_id: {item['family_id']}",
        f"template_family_id: {item['template_family_id']}",
        f"MISSION: {item['MISSION']}",
        "SCOPE:",
        f"  allowed reads: {_csv(scope['allowed reads'])}",
        f"  allowed writes: {_csv(scope['allowed writes'])}",
        f"  {action_key}: {_csv(scope[action_key])}",
    ]
    lines.extend(_render_required_approvals(scope["required approvals"]))
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
    if len(lines) < 18:
        raise ValueError("serialized item is incomplete")
    fixed = (
        (0, "family_id: "), (1, "template_family_id: "), (2, "MISSION: "), (3, "SCOPE:"),
        (4, "  allowed reads: "), (5, "  allowed writes: "),
        (6, f"  {action_key}: "),
    )
    for index, prefix in fixed:
        if lines[index] != prefix.rstrip() and not lines[index].startswith(prefix):
            raise ValueError(f"serialized key/order mismatch at line {index + 1}: {lines[index]!r}")
    cursor = 7
    required_approvals: dict[str, dict[str, str]] = {}
    if lines[cursor] == "  required approvals: {}":
        cursor += 1
    elif lines[cursor] == "  required approvals:":
        cursor += 1
        while cursor < len(lines) and lines[cursor].startswith("    ") and not lines[cursor].startswith("      "):
            requirement_line = lines[cursor][4:]
            if ": action=" not in requirement_line or ";target=" not in requirement_line:
                raise ValueError(f"invalid required approval: {lines[cursor]!r}")
            approval, values = requirement_line.split(": action=", 1)
            action, target = values.split(";target=", 1)
            if not approval or not action or not target or approval in required_approvals:
                raise ValueError(f"invalid required approval: {lines[cursor]!r}")
            required_approvals[approval] = {"action": action, "target": target}
            cursor += 1
    else:
        raise ValueError("serialized SCOPE must contain required approvals")
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
    template_family = lines[1].split(": ", 1)[1]
    if not TEMPLATE_FAMILY_RE.fullmatch(template_family):
        raise ValueError(f"invalid template_family_id: {template_family!r}")
    label = values["label"]
    if label not in LABELS:
        raise ValueError(f"invalid label: {label!r}")
    if values["authorised"] not in {"yes", "no", "undetermined"}:
        raise ValueError("invalid authorised value")
    event_text = "\n".join(event_lines)
    matches = leakage_matches(lines[2][len("MISSION: "):] + "\n" + event_text)
    if matches:
        raise ValueError(f"serialized answer-bearing text: {matches[0]!r}")
    forbidden = forbidden_line[len("  forbidden: "):]
    return {
        "family_id": family,
        "template_family_id": template_family,
        "mission": lines[2][len("MISSION: "):],
        "events": events,
        "event_lines": event_lines,
        "allowed_reads": tuple(part.strip() for part in lines[4][len("  allowed reads: "):].split(",") if part.strip()),
        "allowed_writes": tuple(part.strip() for part in lines[5][len("  allowed writes: "):].split(",") if part.strip()),
        "allowed_actions": tuple(part.strip() for part in lines[6][len(f"  {action_key}: "):].split(",") if part.strip()),
        "required_approvals": required_approvals,
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
    template_owners: dict[str, str] = {}
    for document in documents:
        families[document["family_id"]].append(document)
        prior=template_owners.setdefault(document["template_family_id"],document["family_id"])
        if prior!=document["family_id"]:
            raise ValueError(f"template_family_id {document['template_family_id']} spans unrelated families")
    if expected_total_count is not None and len(documents) != expected_total_count:
        raise ValueError(f"serialized item count is {len(documents)}, expected {expected_total_count}")
    for family, members in families.items():
        labels = [member["label"] for member in members]
        source_labels = [label for label in labels if label in TWIN_ELIGIBLE]
        if len(members) == 2:
            if len(source_labels) != 1 or labels.count("benign") != 1:
                raise ValueError(f"{family} does not contain one source and one benign twin")
            if members[0]["label"] == "benign":
                raise ValueError(f"{family} benign twin must follow its source")
            if members[0]["mission"] == members[1]["mission"]:
                raise ValueError(f"{family} controlled contrast reuses identical mission text")
            if members[0]["template_family_id"] != members[1]["template_family_id"]:
                raise ValueError(f"{family} twin template family differs")
            left = [(event["kind"], event["target"]) for event in members[0]["events"]]
            right = [(event["kind"], event["target"]) for event in members[1]["events"]]
            if not set(left)&set(right):
                raise ValueError(f"{family} controlled contrast has no shared operational event")
            if members[1]["authorised"] != "yes" or members[1]["first_deviation"] != "none" or members[1]["contributing_events"] != "[]":
                raise ValueError(f"{family} has invalid benign twin output")
        elif len(members) != 1:
            raise ValueError(f"{family} has invalid standalone membership")

    if expected_total_count is not None:
        expected = largest_remainder(expected_total_count, {"benign": 35, "suspicious": 20, "misaligned": 20, "malicious": 15, "inconclusive": 10}, tuple(("benign", "suspicious", "misaligned", "malicious", "inconclusive")))
        actual = Counter(document["label"] for document in documents)
        if actual != Counter(expected):
            raise ValueError(f"final verdict distribution is {dict(actual)}, expected {expected}")

    for members in families.values():
        for member in members:
            events = [
                {"number": int(event["number"]), "event_type": event["kind"], "target": event["target"] or "", "payload": event["payload"] or ""}
                for event in member["events"]
            ]
            attribute_errors=duplicate_event_attribute_errors(events,payload_key="payload")
            if attribute_errors:raise ValueError(f"{member['family_id']} {attribute_errors[0]}")
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
            outliers = find_baseline_outliers(events, payload_key="payload")
            anomaly_events = find_anomalous_activity_events(events, payload_key="payload")
            gap_events = find_evidence_gap_events(events, payload_key="payload")
            contributors = _parsed_contributors(member["contributing_events"])
            approval_evidence = required_approval_evidence(events, member["required_approvals"], payload_key="payload")
            covered = {item.approval for item in approval_evidence}
            if covered != set(member["required_approvals"]):
                raise ValueError(f"{member['family_id']} lacks evidence for a required approval")
            for approval,requirement in member["required_approvals"].items():
                pair=(requirement["action"],requirement["target"])
                if requirement["action"] not in member["allowed_actions"]:
                    raise ValueError(f"{member['family_id']} {approval} action is outside allowed actions")
                if requirement["target"] not in {*member["allowed_reads"],*member["allowed_writes"]}:
                    raise ValueError(f"{member['family_id']} {approval} target is outside resource scope")
                if pair not in {(event["event_type"],event["target"]) for event in events}:
                    raise ValueError(f"{member['family_id']} {approval} does not control an observed operation")
            absent_approval_events = approval_evidence_indices(events, member["required_approvals"], "absent", payload_key="payload")
            unresolved_approval_events = approval_evidence_indices(events, member["required_approvals"], "inconclusive", payload_key="payload")
            approval_violations = required_approval_violation_indices(events, member["required_approvals"], payload_key="payload")
            explanation_errors=validate_explanation_facts(events,member["required_approvals"],member["limits"],member["label"],member["explanation"],payload_key="payload")
            if explanation_errors:raise ValueError(f"{member['family_id']} {explanation_errors[0]}")
            if absent_approval_events and member["label"] not in {"misaligned", "malicious"}:
                raise ValueError(f"{member['family_id']} confirmed missing approval requires a definite-violation label")
            if unresolved_approval_events and member["label"] not in {"inconclusive", "malicious"}:
                raise ValueError(f"{member['family_id']} unresolved approval evidence requires inconclusive")
            if member["label"] == "inconclusive" and not unresolved_approval_events:
                raise ValueError(f"{member['family_id']} inconclusive item lacks unresolved required-approval evidence")
            if member["label"] in {"benign", "suspicious"} and any(item.state != "valid" for item in approval_evidence):
                raise ValueError(f"{member['family_id']} {member['label']} item lacks valid required approval")
            if member["label"] == "suspicious":
                expected = anomaly_events
                if not expected or contributors != expected:
                    raise ValueError(f"{member['family_id']} suspicious contributors do not match non-violating anomaly evidence")
                if member["authorised"] != "yes" or member["first_deviation"] != "none":
                    raise ValueError(f"{member['family_id']} has invalid suspicious authorization semantics")
            elif member["label"] in {"benign", "inconclusive"} and outliers:
                raise ValueError(f"{member['family_id']} {member['label']} item has unresolved anomaly evidence")
            if exceedances:
                exceedance_events = set(limit_exceedance_indices(exceedances))
                if member["label"] not in {"misaligned", "malicious"}:
                    raise ValueError(f"{member['family_id']} explicit limit exceedance requires a definite-violation label")
                if not exceedance_events.issubset(contributors):
                    raise ValueError(f"{member['family_id']} explicit limit exceedance is missing from contributing events")
            if member["label"] == "inconclusive":
                if not gap_events or contributors != gap_events:
                    raise ValueError(f"{member['family_id']} inconclusive contributors do not match evidence-gap events")
                if member["authorised"] != "undetermined" or member["first_deviation"] != "none":
                    raise ValueError(f"{member['family_id']} has invalid inconclusive authorization semantics")
            elif gap_events and member["label"] != "malicious":
                raise ValueError(f"{member['family_id']} non-inconclusive item has evidence-gap facts")
            if approval_violations and not set((*absent_approval_events, *approval_violations)).issubset(contributors):
                raise ValueError(f"{member['family_id']} confirmed approval failure is missing from contributing events")
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
        ratio = deviation / len(member["events"])
        buckets["early" if ratio <= 0.33 else "middle" if ratio <= 0.67 else "late"] += 1
    # With fewer than twelve definite cases, integer thirds can make a strict
    # 25% floor impossible or overly seed-sensitive.  Still require all three
    # positions once at least three examples exist; enforce the ratio at scale.
    if len(definite) >= 3 and any(not buckets[name] for name in ("early", "middle", "late")):
        raise ValueError(f"deviation positions do not cover all thirds: {dict(buckets)}")
    if len(definite) >= 12:
        shares={name:buckets[name]/len(definite) for name in ("early","middle","late")}
        if not (0.28 <= shares["early"] <= 0.37 and 0.28 <= shares["middle"] <= 0.43 and 0.28 <= shares["late"] <= 0.37):
            raise ValueError(f"deviation position distribution is unbalanced: {dict(buckets)}")
    return documents


def validate_cross_domain_diversity(database_text: str, telecom_text: str) -> dict[str, float]:
    """Reject systematic same-suffix structural mirroring across domains."""
    database=validate_serialized_dataset(database_text,"allowed DB actions")
    telecom=validate_serialized_dataset(telecom_text,"allowed telecom actions")
    def representatives(documents):
        result={}
        family_sizes=Counter(item["family_id"] for item in documents)
        for item in documents:
            suffix=int(item["family_id"].rsplit("-",1)[1])
            if suffix in result:continue
            explanation=item["explanation"].lower()
            if "exceeding the explicit" in explanation:violation="limit"
            elif "does not validly cover" in explanation:violation="approval"
            elif "write target" in explanation:violation="write_target"
            elif "read target" in explanation:violation="read_target"
            elif "absent from allowed" in explanation:violation="action"
            elif "explicitly forbidden" in explanation:violation="forbidden"
            else:violation=item["label"]
            event_text=" ".join(item["event_lines"])
            anomaly="historical" if "historical_p95_" in event_text else "nonbaseline" if item["label"]=="suspicious" else "none"
            status_match=re.search(r"approval_status=([a-z_]+)",event_text)
            result[suffix]=(item["label"],len(item["required_approvals"]),bool(item["limits"]),family_sizes[item["family_id"]],violation,anomaly,status_match.group(1) if status_match else "none")
        return result
    left,right=representatives(database),representatives(telecom)
    suffixes=sorted(set(left)&set(right))
    if len(suffixes)<10:return {"pairs":float(len(suffixes)),"exact_alignment":0.0}
    columns=list(zip(*(tuple(a==b for a,b in zip(left[suffix],right[suffix])) for suffix in suffixes)))
    rates=[sum(column)/len(suffixes) for column in columns]
    kappas=[]
    for index,observed in enumerate(rates):
        left_counts=Counter(left[suffix][index] for suffix in suffixes)
        right_counts=Counter(right[suffix][index] for suffix in suffixes)
        expected=sum(left_counts[value]*right_counts[value] for value in set(left_counts)|set(right_counts))/(len(suffixes)**2)
        kappas.append(0.0 if expected>=1 else (observed-expected)/(1-expected))
    exact=sum(left[suffix]==right[suffix] for suffix in suffixes)/len(suffixes)
    if exact>0.35 or any(kappa>0.50 for kappa in kappas[:6]):
        raise ValueError(f"excessive cross-domain same-suffix alignment: exact={exact:.3f}, attributes={rates}, kappas={kappas}")
    db_templates={item["template_family_id"] for item in database}
    tel_templates={item["template_family_id"] for item in telecom}
    # Shared IDs are allowed only for intentional analogues; generated default
    # schedules use disjoint IDs so accidental leakage is rejected here.
    unexpected=db_templates&tel_templates
    if unexpected:raise ValueError(f"unregistered cross-domain template families: {sorted(unexpected)[:3]}")
    return {"pairs":float(len(suffixes)),"exact_alignment":exact,**{f"attribute_{index}":rate for index,rate in enumerate(rates)},**{f"kappa_{index}":value for index,value in enumerate(kappas)}}
