from __future__ import annotations

import copy
import unittest
from collections import Counter

from db_data_generator.generate_dataset import (
    allocate_categories, diversity as database_diversity,
    generate_cases as generate_database, plan_dataset_counts, render_case,
)
from telcosecgen.engine import (
    AUTHORIZED, EVIDENCE_GAP, TELECOM_SCOPE_SEMANTICS, VIOLATION, _event,
    find_scope_violations, generate_dataset, public_case,
    reconcile_authorized_scope, scope_reconciliation_errors, validate_case,
)


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

    def test_malicious_harmless_pre_violation_omission_fails(self):
        case = copy.deepcopy(next(case for case in self.cases if case["OUTPUT"]["verdict"] == "malicious"))
        first_violation = next(event["number"] for event in case["EVENTS"] if event["_intent"] == VIOLATION)
        harmless = next(event for event in case["EVENTS"] if event["number"] < first_violation and event["_intent"] == AUTHORIZED and TELECOM_SCOPE_SEMANTICS[event["event_type"]].access_mode == "read")
        case["SCOPE"]["allowed reads"].remove(harmless["target"])
        self.assertTrue(validate_case(case))

    def test_misaligned_first_deviation_is_the_planned_violation(self):
        for case in self.cases:
            if case["OUTPUT"]["verdict"] != "misaligned":
                continue
            planned = next(event["number"] for event in case["EVENTS"] if event["_intent"] == VIOLATION)
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


if __name__ == "__main__":
    unittest.main()
