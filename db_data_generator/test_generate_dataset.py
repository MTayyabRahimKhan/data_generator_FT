import copy
import tempfile
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path

from db_data_generator.generate_dataset import (
    ENGINES, allocate_categories, allocate_engines, allocate_mission_outcomes,
    diversity, generate_cases, load_config, render_case, run_generation,
    serialize_cases, validate_case, validate_cases,
)


class DatabaseGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases = generate_cases(100, 42)

    def test_exact_distribution_and_count(self):
        self.assertEqual(len(self.cases), 100)
        self.assertEqual(Counter(c.output.verdict for c in self.cases), Counter(allocate_categories(100)))
        for size in (1, 5, 10, 73, 101):
            self.assertEqual(sum(allocate_categories(size).values()), size)
            self.assertEqual(sum(allocate_engines(size).values()), size)
            self.assertEqual(sum(allocate_mission_outcomes(size).values()), size)

    def test_selective_adjacency_uses_existing_benign_cases(self):
        marked = [c for c in self.cases if c.adjacent_benign_id]
        malicious = [c for c in self.cases if c.output.verdict == "malicious"]
        self.assertEqual(sum(c.output.verdict == "malicious" for c in marked), 9)
        self.assertLess(sum(c.output.verdict == "malicious" for c in marked), len(malicious))
        self.assertEqual(len({c.adjacent_benign_id for c in marked}), len(marked))
        self.assertEqual(Counter(c.output.verdict for c in self.cases)["benign"], 35)
        positions = {c.case_id: i for i, c in enumerate(self.cases)}
        by_id = {c.case_id: c for c in self.cases}
        directions = set()
        for severe in marked:
            directions.add(severe.adjacency_direction)
            self.assertEqual(by_id[severe.adjacent_benign_id].output.verdict, "benign")
            offset = -1 if severe.adjacency_direction == "before" else 1
            self.assertEqual(positions[severe.adjacent_benign_id], positions[severe.case_id] + offset)
            self.assertGreaterEqual(diversity(severe, by_id[severe.adjacent_benign_id]), 0.10)
        self.assertEqual(directions, {"before", "after"})

    def test_only_eligible_cases_are_selected(self):
        for case in self.cases:
            if case.output.verdict in {"suspicious", "inconclusive"} or (case.output.verdict == "misaligned" and case.severity_level == "medium"):
                self.assertIsNone(case.adjacent_benign_id)

    def test_configurable_rate_and_disabled_mode(self):
        config = copy.deepcopy(load_config(Path(__file__).with_name("generator_config.json")))
        config["severe_case_adjacency"].update({"malicious_rate": 0, "severe_misaligned_rate": 0})
        self.assertFalse(any(c.adjacent_benign_id for c in generate_cases(100, 42, config)))
        config["severe_case_adjacency"].update({"malicious_rate": 1, "severe_misaligned_rate": 1})
        selected = [c for c in generate_cases(100, 42, config) if c.adjacent_benign_id]
        self.assertLessEqual(len(selected), 35)

    def test_seed_reproducibility_and_small_dataset(self):
        self.assertEqual(generate_cases(25, 7), generate_cases(25, 7))
        self.assertNotEqual(generate_cases(25, 7), generate_cases(25, 8))
        self.assertEqual(len(generate_cases(1, 7)), 1)

    def test_global_pairwise_diversity(self):
        for index, case in enumerate(self.cases):
            for prior in self.cases[:index]:
                self.assertGreaterEqual(diversity(case, prior), 0.10)

    def test_no_counterfactual_schema_or_serialization(self):
        rendered = serialize_cases(self.cases)
        self.assertNotIn("COUNTERFACTUAL", rendered.upper())
        self.assertNotIn("pair_id", rendered)
        self.assertNotIn("paired_case_id", rendered)
        self.assertEqual(rendered.count("CASE_ID:"), 100)

    def test_semantic_validation_still_rejects_bad_case(self):
        case = next(c for c in self.cases if c.output.verdict == "malicious")
        with self.assertRaises(ValueError):
            validate_case(replace(case, output=replace(case.output, authorised="yes")))
        validate_cases(self.cases, 100)

    def test_scope_contains_roles(self):
        self.assertTrue(all(c.scope.allowed_roles and c.scope.forbidden_roles for c in self.cases))
        self.assertIn("allowed roles:", render_case(self.cases[0]))

    def test_end_to_end_write(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "database.yaml"
            cases = run_generation(25, output, 17)
            self.assertEqual(len(cases), 25)
            self.assertTrue(output.exists())


if __name__ == "__main__":
    unittest.main()
