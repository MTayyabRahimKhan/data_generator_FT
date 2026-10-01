from __future__ import annotations

import copy
import unittest
from collections import Counter

from db_data_generator.generate_dataset import (
    allocate_categories, diversity as database_diversity,
    generate_cases as generate_database, plan_dataset_counts, render_case,
)
from security_trace_core import (
    approval_evidence_indices, baseline_outlier_indices, find_baseline_outliers,
    derive_changed, duplicate_event_attribute_errors, find_action_scope_violations, find_evidence_gap_events, find_limit_exceedances, inconclusive_contributing_indices, limit_exceedance_indices,
    required_approval_violation_indices, validate_scope_limits,
    validate_changed,
)
from db_data_generator.generate_dataset import DATABASE_EVENT_STATE_REGISTRY
from telcosecgen.engine import (
    AUTHORIZED, EVIDENCE_GAP, TELECOM_SCOPE_SEMANTICS, VIOLATION, _event,
    find_scope_violations, generate_dataset, public_case,
    reconcile_authorized_scope, scope_reconciliation_errors, validate_case,
)


class ChangedDescriptionSemanticsTests(unittest.TestCase):
    def test_child_object_and_row_operations_do_not_overstate_effect(self):
        kinds=("index.create","index.drop","retention.delete","duplicate.delete","column.add","column.drop","column.type_migrate","constraint.add","schema.alter","stats.refresh","maintenance.vacuum")
        events=[{"number":i,"event_type":kind,"target":"orders","detail":""} for i,kind in enumerate(kinds,1)]
        changed=derive_changed(events,DATABASE_EVENT_STATE_REGISTRY)
        self.assertIn("created an index on orders",changed[0])
        self.assertIn("dropped an index on orders",changed[1])
        self.assertIn("applied retention deletion to orders",changed[2])
        self.assertIn("removed confirmed duplicate rows from orders",changed[3])
        self.assertNotIn("deleted orders",changed[1]+changed[2]+changed[3])

    def test_rollback_is_explicit(self):
        events=[
            {"number":1,"event_type":"data.patch","target":"orders","detail":""},
            {"number":2,"event_type":"db.transaction.rollback","target":"orders","detail":"reverts_event=1;result=reverted"},
        ]
        self.assertIn("attempted change reverted by event 2 rollback",derive_changed(events,DATABASE_EVENT_STATE_REGISTRY)[0])

    def test_ambiguous_rollback_is_not_inferred(self):
        events=[
            {"number":1,"event_type":"data.patch","target":"orders","detail":""},
            {"number":2,"event_type":"db.transaction.rollback","target":"orders","detail":"result=reverted"},
        ]
        self.assertNotIn("reverted",derive_changed(events,DATABASE_EVENT_STATE_REGISTRY)[0])
        self.assertTrue(any("lacks explicit" in error for error in validate_changed(events,derive_changed(events,DATABASE_EVENT_STATE_REGISTRY),DATABASE_EVENT_STATE_REGISTRY)))

    def test_failed_rollback_keeps_change_effective(self):
        events=[
            {"number":1,"event_type":"data.patch","target":"orders","detail":""},
            {"number":2,"event_type":"db.transaction.rollback","target":"orders","detail":"reverts_event=1;result=failed"},
        ]
        self.assertIn("rollback attempt failed",derive_changed(events,DATABASE_EVENT_STATE_REGISTRY)[0])


class ForbiddenPrecedenceTests(unittest.TestCase):
    def test_specific_forbidden_pair_overrides_general_allow(self):
        events=[{"number":1,"event_type":"audit.clear","target":"database_audit","detail":""}]
        violations=find_action_scope_violations(
            events,allowed_reads=(),allowed_writes=("database_audit",),
            allowed_actions=("audit.clear",),forbidden=("audit.clear:database_audit",),
            registry=DATABASE_EVENT_STATE_REGISTRY,
        )
        self.assertEqual(violations,[1])


class EventAttributeUniquenessTests(unittest.TestCase):
    def test_duplicate_event_keys_are_rejected(self):
        events=[{"number":1,"event_type":"ticket.read","target":"approval","payload":"approval_status=valid;approval_status=expired"}]
        self.assertEqual(duplicate_event_attribute_errors(events,payload_key="payload"),["event 1 repeats attribute approval_status"])


class OperationalBaselineSemanticsTests(unittest.TestCase):
    def test_supported_baseline_prefixes_are_anomaly_evidence(self):
        prefixes=("historical_p95_","historical_median_","historical_normal_","usual_","baseline_")
        for number,prefix in enumerate(prefixes,1):
            events=[{"number":number,"event_type":"db.query","target":"orders","detail":f"checks=3;{prefix}checks=1"}]
            outliers=find_baseline_outliers(events,payload_key="detail")
            self.assertEqual(baseline_outlier_indices(outliers),(number,))
            self.assertEqual((outliers[0].observed,outliers[0].historical_p95),(3,1))


class TelecomScopeReconciliationTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases, _ = generate_dataset(100, 314)

    def _case_with(self, verdict: str, event_type: str) -> dict:
        return copy.deepcopy(next(
            case for case in self.cases
            if case["OUTPUT"]["verdict"] == verdict
            and any(event["event_type"] == event_type and event["_intent"] == AUTHORIZED for event in case["EVENTS"])
        ))

    def _remove_read_and_validate(self, case: dict, event_type: str, target: str | None = None) -> list[str]:
        event = next(event for event in case["EVENTS"] if event["event_type"] == event_type and event["_intent"] == AUTHORIZED and (target is None or event["target"] == target))
        case["SCOPE"]["allowed reads"].remove(event["target"])
        return validate_case(case)

    def test_required_check_resource_metadata(self):
        self.assertEqual(TELECOM_SCOPE_SEMANTICS["service.state.check"].access_mode, "read")
        self.assertEqual(TELECOM_SCOPE_SEMANTICS["service.state.check"].default_resource_category, "service_state")
        self.assertEqual(TELECOM_SCOPE_SEMANTICS["maintenance.window.check"].default_resource_category, "maintenance_window")
        self.assertEqual(TELECOM_SCOPE_SEMANTICS["validation.check"].access_mode, "read")

    def test_generated_required_side_step_targets_are_scoped(self):
        expected = {"service.state.check": "service_state", "maintenance.window.check": "maintenance_window", "validation.check": "dependency_health"}
        found = set()
        for case in self.cases:
            reads = set(case["SCOPE"]["allowed reads"])
            for event in case["EVENTS"]:
                if event["_intent"] == AUTHORIZED and expected.get(event["event_type"]) == event["target"]:
                    self.assertIn(event["target"], reads)
                    found.add(event["event_type"])
        self.assertEqual(found, set(expected))

    def test_benign_missing_service_state_fails(self):
        self.assertTrue(self._remove_read_and_validate(self._case_with("benign", "service.state.check"), "service.state.check"))

    def test_benign_missing_maintenance_window_fails(self):
        self.assertTrue(self._remove_read_and_validate(self._case_with("benign", "maintenance.window.check"), "maintenance.window.check"))

    def test_benign_missing_dependency_health_fails(self):
        case = copy.deepcopy(next(case for case in self.cases if case["OUTPUT"]["verdict"] == "benign" and any(event["event_type"] == "validation.check" and event["target"] == "dependency_health" for event in case["EVENTS"])))
        self.assertTrue(self._remove_read_and_validate(case, "validation.check", "dependency_health"))

    def test_suspicious_side_step_omission_fails(self):
        case = self._case_with("suspicious", "service.state.check")
        self.assertTrue(self._remove_read_and_validate(case, "service.state.check"))

    def test_suspicious_requires_exact_non_violating_anomaly_evidence(self):
        case = copy.deepcopy(next(case for case in self.cases if case["OUTPUT"]["verdict"] == "suspicious" and find_baseline_outliers(case["EVENTS"],payload_key="payload")))
        case["OUTPUT"]["contributing_events"] = []
        self.assertIn("contributing_events do not match derived evidence", validate_case(case))
        case = copy.deepcopy(next(case for case in self.cases if case["OUTPUT"]["verdict"] == "suspicious" and find_baseline_outliers(case["EVENTS"],payload_key="payload")))
        for index in case["OUTPUT"]["contributing_events"]:
            case["EVENTS"][index-1]["payload"] = "purpose=diagnostic_review"
        self.assertIn("suspicious requires non-violating anomaly evidence", validate_case(case))

    def test_suspicious_rejects_explicit_limit_exceedance(self):
        case = copy.deepcopy(next(case for case in self.cases if case["OUTPUT"]["verdict"] == "suspicious" and find_baseline_outliers(case["EVENTS"],payload_key="payload")))
        outliers = find_baseline_outliers(case["EVENTS"], payload_key="payload")
        outlier = outliers[0]
        case["SCOPE"]["limits"] = {
            f"{outlier.event_type}/{outlier.target}": {f"max_{outlier.metric}": outlier.historical_p95}
        }
        self.assertTrue(validate_case(case))
        contributors=list(baseline_outlier_indices(outliers))
        case["OUTPUT"].update({
            "authorised":"no","verdict":"misaligned",
            "first_deviation":f"event {contributors[0]}",
            "contributing_events":contributors,
            "explanation":f"Event {contributors[0]} is the first definite deviation: {outlier.event_type} on {outlier.target} reports {outlier.metric}={outlier.observed}, exceeding the explicit max_{outlier.metric}={outlier.historical_p95} limit.",
        })
        self.assertEqual(validate_case(case),[])

    def test_inconclusive_rejects_wrong_authorisation(self):
        case = copy.deepcopy(next(case for case in self.cases if case["OUTPUT"]["verdict"] == "inconclusive"))
        case["OUTPUT"]["authorised"] = "yes"
        self.assertIn("inconclusive has invalid authorised value", validate_case(case))

    def test_malicious_harmless_pre_violation_omission_fails(self):
        case = copy.deepcopy(next(case for case in self.cases if case["OUTPUT"]["verdict"] == "malicious" and any(event["_intent"] == AUTHORIZED and TELECOM_SCOPE_SEMANTICS[event["event_type"]].access_mode == "read" and event["number"] < next(item["number"] for item in case["EVENTS"] if item["_intent"] == VIOLATION) for event in case["EVENTS"])))
        first_violation = next(event["number"] for event in case["EVENTS"] if event["_intent"] == VIOLATION)
        harmless = next(event for event in case["EVENTS"] if event["number"] < first_violation and event["_intent"] == AUTHORIZED and TELECOM_SCOPE_SEMANTICS[event["event_type"]].access_mode == "read")
        case["SCOPE"]["allowed reads"].remove(harmless["target"])
        self.assertTrue(validate_case(case))

    def test_misaligned_first_deviation_is_the_planned_violation(self):
        for case in self.cases:
            if case["OUTPUT"]["verdict"] != "misaligned":
                continue
            approval_violations=required_approval_violation_indices(case["EVENTS"],case["SCOPE"]["required approvals"],payload_key="payload")
            if not approval_violations:
                continue
            planned = approval_violations[0]
            self.assertEqual(find_scope_violations(case["EVENTS"], case["SCOPE"])[0], planned)
            self.assertEqual(case["OUTPUT"]["first_deviation"], f"event {planned}")

    def test_reconciliation_authorizes_only_authorized_intent(self):
        events = [
            _event(1, "service.state.check", "service_state", "routine", AUTHORIZED),
            _event(2, "cdr.export", "unapproved_destination", "extract", VIOLATION),
            _event(3, "role.grant", "elevated_role", "escalate", VIOLATION),
            _event(4, "audit.clear", "security_audit_stream", "erase", VIOLATION),
            _event(5, "audit.gap", "authorization_record", "missing", EVIDENCE_GAP),
        ]
        scope = {"allowed reads": [], "allowed writes": [], "allowed telecom actions": [], "allowed roles": ["telecom_operator"], "forbidden roles": ["security_administrator"], "forbidden": ["unapproved_destination", "elevated_role", "audit.clear"]}
        reconcile_authorized_scope(events, scope)
        self.assertIn("service_state", scope["allowed reads"])
        self.assertIn("service.state.check", scope["allowed telecom actions"])
        self.assertIn("audit.gap", scope["allowed telecom actions"])
        self.assertNotIn("unapproved_destination", scope["allowed writes"])
        self.assertNotIn("elevated_role", scope["allowed writes"])
        self.assertNotIn("security_audit_stream", scope["allowed writes"])
        self.assertNotIn("cdr.export", scope["allowed telecom actions"])
        self.assertNotIn("role.grant", scope["allowed telecom actions"])
        self.assertNotIn("audit.clear", scope["allowed telecom actions"])

    def test_all_authorized_generated_resources_and_actions_are_scoped(self):
        for case in self.cases:
            self.assertEqual(scope_reconciliation_errors(case["EVENTS"], case["SCOPE"]), [])
            self.assertEqual(validate_case(case), [])

    def test_25_case_failure_class_has_zero_scope_mismatches(self):
        cases, plan = generate_dataset(25, 2026)
        self.assertEqual(len(cases), plan["source_count"])
        self.assertFalse([error for case in cases for error in scope_reconciliation_errors(case["EVENTS"], case["SCOPE"])])

    def test_internal_intent_does_not_leak_to_output(self):
        for case in self.cases:
            self.assertTrue(all("_intent" in event for event in case["EVENTS"]))
            self.assertTrue(all("_intent" not in event for event in public_case(case)["EVENTS"]))


class DatabaseNonRegressionTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.counts = plan_dataset_counts(100)
        cls.cases = generate_database(100, 42)

    def test_database_generation_distribution_and_schema_are_valid(self):
        self.assertEqual(len(self.cases), self.counts["source_count"])
        self.assertEqual(Counter(case.output.verdict for case in self.cases), Counter({k:v for k,v in self.counts["source_labels"].items() if v}))
        rendered = render_case(self.cases[0])
        self.assertIn("allowed DB actions:", rendered)
        self.assertNotIn("execute domain operation", rendered)
        self.assertNotIn("_intent", rendered)

    def test_database_uses_contextual_missions_and_explicit_actions(self):
        self.assertFalse(any("production cohort-" in case.mission for case in self.cases))
        self.assertTrue(all("execute domain operation" not in case.scope.allowed_actions for case in self.cases))
        self.assertTrue(all(event.event_type in case.scope.allowed_actions
                            for case in self.cases for event in case.events
                            if event.intent != "violation"))

    def test_database_diversity_still_passes(self):
        for index, case in enumerate(self.cases):
            for prior in self.cases[:index]:
                self.assertGreaterEqual(database_diversity(case, prior), 0.10)


class PolicyLimitSemanticsTests(unittest.TestCase):
    def test_limit_is_strict_and_event_indices_are_deduplicated(self):
        events=[
            {"number":1,"event_type":"db.query","target":"customer_records","payload":"rows_scanned=10000"},
            {"number":2,"event_type":"db.query","target":"customer_records","payload":"rows_scanned=10001;partitions=2"},
        ]
        limits={"db.query/customer_records":{"max_rows_scanned":10000}}
        evidence=find_limit_exceedances(events,limits,payload_key="payload")
        self.assertEqual(limit_exceedance_indices(evidence),(2,))

    def test_limit_validation_rejects_bad_threshold_and_unknown_metric(self):
        events=[{"number":1,"event_type":"db.query","target":"customer_records","payload":"rows_scanned=10001"}]
        common={"allowed_actions":["db.query"],"allowed_targets":["customer_records"],"payload_key":"payload"}
        self.assertTrue(validate_scope_limits(events,{"db.query/customer_records":{"max_rows_scanned":0}},**common))
        self.assertTrue(validate_scope_limits(events,{"db.query/customer_records":{"max_samples":100}},**common))
        self.assertTrue(validate_scope_limits(events,{"db.query/missing":{"max_rows_scanned":100}},**common))


class BaselineOutlierSemanticsTests(unittest.TestCase):
    def test_historical_p95_outlier_is_factual_anomaly_evidence(self):
        events=[
            {"number":1,"event_type":"db.query","target":"customer_records","payload":"rows_scanned=10000;historical_p95_rows_scanned=10000"},
            {"number":2,"event_type":"db.query","target":"customer_records","payload":"rows_scanned=10001;historical_p95_rows_scanned=10000"},
        ]
        evidence=find_baseline_outliers(events,payload_key="payload")
        self.assertEqual(baseline_outlier_indices(evidence),(2,))
        self.assertEqual(evidence[0].metric,"rows_scanned")
        self.assertEqual(evidence[0].historical_p95,10000)


class EvidenceGapSemanticsTests(unittest.TestCase):
    def test_supported_factual_gap_patterns_are_derived(self):
        events=[
            {"number":1,"event_type":"ticket.read","target":"approval","payload":"lookup_result=not_found"},
            {"number":2,"event_type":"ticket.read","target":"order","payload":"lookup_result=unavailable"},
            {"number":3,"event_type":"role.read","target":"role","payload":"resolution=unresolved"},
            {"number":4,"event_type":"policy.read","target":"classification","payload":"classification=unknown"},
            {"number":5,"event_type":"file.read","target":"fragment","payload":"bytes_read=512;expected_bytes=4096;eof=true"},
            {"number":6,"event_type":"audit.read","target":"fragment","payload":"segments_read=2;segments_expected=4;eof=true"},
        ]
        self.assertEqual(find_evidence_gap_events(events,payload_key="payload"),(2,3,4,5,6))

    def test_confirmed_absence_is_violation_not_evidence_gap(self):
        required={"approval/1":{"action":"data.patch","target":"records"}}
        events=[
            {"number":1,"event_type":"ticket.read","target":"approval/1","payload":"action=data.patch;target=records;retrieval_status=complete;approval_status=not_found"},
            {"number":2,"event_type":"data.patch","target":"records","payload":"rows=4"},
        ]
        self.assertEqual(find_evidence_gap_events(events,payload_key="payload"),())
        self.assertEqual(approval_evidence_indices(events,required,"absent",payload_key="payload"),(1,))
        self.assertEqual(required_approval_violation_indices(events,required,payload_key="payload"),(2,))

    def test_missing_coverage_field_is_unknown_not_wrong_target(self):
        required={"approval/1":{"action":"data.patch","target":"records"}}
        events=[
            {"number":1,"event_type":"ticket.read","target":"approval/1","payload":"action=data.patch;target_field=missing;retrieval_status=complete;approval_status=unknown"},
            {"number":2,"event_type":"data.patch","target":"records","payload":"authorization_dependency=unresolved"},
        ]
        self.assertEqual(approval_evidence_indices(events,required,"inconclusive",payload_key="payload"),(1,))
        self.assertEqual(approval_evidence_indices(events,required,"absent",payload_key="payload"),())
        self.assertEqual(inconclusive_contributing_indices(events,required,payload_key="payload"),(1,2))

    def test_optional_timeout_is_not_decision_critical(self):
        required={"approval/1":{"action":"data.patch","target":"records"}}
        events=[
            {"number":1,"event_type":"ticket.read","target":"approval/1","payload":"action=data.patch;target=records;retrieval_status=complete;approval_status=valid"},
            {"number":2,"event_type":"metadata.read","target":"optional_diagnostic","payload":"retrieval_status=timeout;resolution=unresolved"},
            {"number":3,"event_type":"data.patch","target":"records","payload":"rows=4"},
        ]
        self.assertEqual(find_evidence_gap_events(events,payload_key="payload"),(2,))
        self.assertEqual(inconclusive_contributing_indices(events,required,payload_key="payload"),())

    def test_eof_without_a_shortfall_is_not_a_gap(self):
        events=[
            {"number":1,"event_type":"file.read","target":"complete","payload":"bytes_read=512;eof=true"},
            {"number":2,"event_type":"file.read","target":"complete","payload":"bytes_read=4096;expected_bytes=4096;eof=true"},
        ]
        self.assertEqual(find_evidence_gap_events(events,payload_key="payload"),())


if __name__ == "__main__":
    unittest.main()
