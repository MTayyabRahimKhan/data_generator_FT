from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

import yaml

from security_trace_core import DiversityFeatures, validate_pairwise_diversity


ROOT = Path(__file__).resolve().parents[1]
EXPECTED = {"benign": 35, "suspicious": 20, "misaligned": 20, "malicious": 15, "inconclusive": 10}


def features(case: dict) -> DiversityFeatures:
    scope = case["SCOPE"]
    return DiversityFeatures(
        case["MISSION"],
        tuple(f"{event['event_type']}:{event['target']}" for event in case["EVENTS"]),
        tuple(scope["allowed roles"]),
        tuple(scope["forbidden roles"]),
    )


class UnifiedEndToEndTests(unittest.TestCase):
    def test_database_and_telecom_at_25_100_and_1000(self):
        with tempfile.TemporaryDirectory() as directory:
            for domain in ("database", "telecom"):
                for total in (25, 100, 1000):
                    with self.subTest(domain=domain, total=total):
                        output = Path(directory) / f"{domain}_dataset.yaml"
                        result = subprocess.run(
                            [sys.executable, str(ROOT / "generate_dataset.py"), "--domain", domain, "--cases", str(total), "--seed", "2026"],
                            cwd=directory, text=True, capture_output=True,
                        )
                        self.assertEqual(result.returncode, 0, result.stderr)
                        documents = list(yaml.safe_load_all(output.read_text(encoding="utf-8")))
                        self.assertEqual(len(documents), total)
                        # Generator-specific largest-remainder allocation is
                        # already validated before serialization.  Recompute it
                        # here for arbitrary sizes, including N=25.
                        quotas = {key: total * percentage / 100 for key, percentage in EXPECTED.items()}
                        expected = {key: int(value) for key, value in quotas.items()}
                        for key in sorted(EXPECTED, key=lambda item: -(quotas[item] - expected[item]))[:total-sum(expected.values())]:
                            expected[key] += 1
                        self.assertEqual(Counter(doc["OUTPUT"]["verdict"] for doc in documents), expected)
                        ids = [doc["CASE_ID"] for doc in documents]
                        self.assertEqual(len(ids), len(set(ids)))
                        self.assertNotIn("COUNTERFACTUAL", output.read_text(encoding="utf-8").upper())
                        validate_pairwise_diversity(documents, features, lambda doc: doc["CASE_ID"])
                        self.assertIn("Selective adjacencies:", result.stdout)
                        self.assertIn("Validation: passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
