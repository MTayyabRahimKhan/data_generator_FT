import json
import tempfile
import unittest
from pathlib import Path

from telco_data_gen import generate


class GeneratorTests(unittest.TestCase):
    def config(self, count: int = 100) -> dict:
        return {
            "total_cases": count,
            "output_file": "output.txt",
            "seed": 42,
            "shuffle_cases": False,
            "distribution_percent": {
                "aligned": 70,
                "single_violation": 15,
                "contextual_violation": 10,
                "threat_escalation": 5,
            },
        }

    def test_exact_distribution_for_requested_sizes(self) -> None:
        for total, expected in (
            (100, [70, 15, 10, 5]),
            (200, [140, 30, 20, 10]),
            (500, [350, 75, 50, 25]),
        ):
            cases, counts = generate.generate_cases(self.config(total))
            self.assertEqual(len(cases), total)
            self.assertEqual(list(counts.values()), expected)

    def test_cases_are_unique_and_separated_cleanly(self) -> None:
        cases, _ = generate.generate_cases(self.config(500))
        self.assertEqual(len(set(cases)), 500)
        rendered = "\n---\n".join(cases)
        self.assertEqual(rendered.count("\n---\n"), 499)
        self.assertNotIn("```", rendered)

    def test_verdict_and_first_deviation_consistency(self) -> None:
        cases, counts = generate.generate_cases(self.config())
        aligned = cases[: counts["aligned"]]
        misaligned = cases[counts["aligned"] :]
        for case in aligned:
            self.assertIn("authorised: yes", case)
            self.assertIn("first_deviation: none", case)
            self.assertIn("contributing_events: []", case)
            self.assertIn("label: aligned", case)
        for case in misaligned:
            self.assertIn("authorised: no.", case)
            self.assertNotIn("first_deviation: none", case)
            self.assertIn("label: misaligned", case)

        contextual_start = counts["aligned"] + counts["single_violation"]
        contextual_end = contextual_start + counts["contextual_violation"]
        for case in cases[contextual_start:contextual_end]:
            self.assertIn("first_deviation: event 3", case)
            self.assertIn('"file.write"', case)
            staging_target = case.split("  2  file.write  ", 1)[1].split("  ", 1)[0]
            allowed_writes = case.split("  allowed writes: ", 1)[1].splitlines()[0]
            self.assertIn(staging_target, allowed_writes)

    def test_seed_is_reproducible(self) -> None:
        first, _ = generate.generate_cases(self.config())
        second, _ = generate.generate_cases(self.config())
        self.assertEqual(first, second)

    def test_invalid_config_is_rejected(self) -> None:
        config = self.config()
        config["distribution_percent"]["aligned"] = 69
        with self.assertRaisesRegex(ValueError, "add up to 100"):
            generate.validate_config(config)

    def test_cli_writes_requested_number_of_cases(self) -> None:
        with tempfile.TemporaryDirectory() as temp_dir:
            config_path = Path(temp_dir) / "config.json"
            output_path = Path(temp_dir) / "cases.txt"
            config_path.write_text(json.dumps(self.config(20)), encoding="utf-8")
            result = generate.main(["--config", str(config_path), "--count", "25", "--output", str(output_path)])
            self.assertEqual(result, 0)
            self.assertEqual(output_path.read_text(encoding="utf-8").count("MISSION:"), 25)


if __name__ == "__main__":
    unittest.main()
