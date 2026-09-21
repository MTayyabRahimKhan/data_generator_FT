from __future__ import annotations

import copy
import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

import yaml

from telcosecgen.engine import (
    VERDICTS, adjacency_records, allocate_largest_remainder, diversity,
    generate_dataset, load_config, public_case, semantic_critic, validate_case,
    validate_dataset,
)


class TelecomGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases, cls.plan = generate_dataset(100, 42)

    def test_exact_distribution_and_count(self):
        expected = dict(zip(VERDICTS, (35, 20, 20, 15, 10)))
        self.assertEqual(len(self.cases), 100)
        self.assertEqual(Counter(c["OUTPUT"]["verdict"] for c in self.cases), expected)
        self.assertEqual(allocate_largest_remainder(101, expected, VERDICTS), {"benign": 36, "suspicious": 20, "misaligned": 20, "malicious": 15, "inconclusive": 10})

    def test_selective_adjacency_before_after_and_no_reuse(self):
        records = adjacency_records(self.cases)
        self.assertEqual(sum(next(c for c in self.cases if c["CASE_ID"] == r.severe_case_id)["OUTPUT"]["verdict"] == "malicious" for r in records), 9)
        self.assertLess(9, 15)
        self.assertEqual(len({r.benign_case_id for r in records}), len(records))
        self.assertEqual({r.direction for r in records}, {"before", "after"})
        positions = {c["CASE_ID"]: i for i, c in enumerate(self.cases)}
        by_id = {c["CASE_ID"]: c for c in self.cases}
        for record in records:
            offset = -1 if record.direction == "before" else 1
            self.assertEqual(positions[record.benign_case_id], positions[record.severe_case_id] + offset)
            self.assertEqual(by_id[record.benign_case_id]["OUTPUT"]["verdict"], "benign")
            self.assertGreaterEqual(diversity(by_id[record.benign_case_id], by_id[record.severe_case_id]), 0.10)

    def test_noneligible_cases_do_not_require_adjacency(self):
        for case in self.cases:
            verdict = case["OUTPUT"]["verdict"]
            severity = case["_meta"]["severity_level"]
            if verdict in {"suspicious", "inconclusive"} or (verdict == "misaligned" and severity == "medium"):
                self.assertNotIn("adjacency", case["_meta"])

    def test_configurable_rates_and_benign_cap(self):
        config = copy.deepcopy(load_config())
        config["severe_case_adjacency"].update({"malicious_rate": 0, "severe_misaligned_rate": 0})
        cases, plan = generate_dataset(100, 42, config)
        self.assertEqual(plan["adjacency"]["selected"], 0)
        self.assertFalse(adjacency_records(cases))
        config["severe_case_adjacency"].update({"malicious_rate": 1, "severe_misaligned_rate": 1})
        _, plan = generate_dataset(100, 42, config)
        self.assertLessEqual(plan["adjacency"]["selected"], 35)

    def test_seed_reproducibility_and_small_dataset(self):
        self.assertEqual(generate_dataset(25, 123), generate_dataset(25, 123))
        self.assertNotEqual(generate_dataset(25, 123), generate_dataset(25, 124))
        self.assertEqual(len(generate_dataset(1, 9)[0]), 1)

    def test_global_pairwise_diversity(self):
        for index, case in enumerate(self.cases):
            for prior in self.cases[:index]:
                self.assertGreaterEqual(diversity(case, prior), 0.10)

    def test_no_counterfactual_or_internal_metadata_in_output(self):
        public = [public_case(case) for case in self.cases]
        rendered = yaml.safe_dump_all(public)
        self.assertNotIn("COUNTERFACTUAL", rendered.upper())
        self.assertNotIn("pair_id", rendered)
        self.assertNotIn("_meta", rendered)
        self.assertTrue(all("allowed roles" in case["SCOPE"] and "forbidden roles" in case["SCOPE"] for case in public))

    def test_semantic_validation_still_runs(self):
        self.assertEqual(validate_dataset(self.cases, 100, load_config()), [])
        self.assertEqual(semantic_critic(self.cases[0]), {"valid": True, "issues": []})
        broken = copy.deepcopy(next(c for c in self.cases if c["OUTPUT"]["verdict"] == "malicious"))
        broken["OUTPUT"]["authorised"] = "yes"
        self.assertTrue(validate_case(broken))

    def test_package_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "telecom.yaml"
            result = subprocess.run([sys.executable, "-m", "telcosecgen", "generate", "--cases", "25", "--output", str(output), "--seed", "7"], text=True, capture_output=True)
            self.assertEqual(result.returncode, 0, result.stderr)
            documents = list(yaml.safe_load_all(output.read_text(encoding="utf-8")))
            self.assertEqual(len(documents), 25)
            self.assertTrue(all("COUNTERFACTUAL" not in document for document in documents))


if __name__ == "__main__":
    unittest.main()
