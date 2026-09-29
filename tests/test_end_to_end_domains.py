from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from security_trace_format import validate_cross_domain_diversity, validate_serialized_dataset


ROOT=Path(__file__).resolve().parents[1]


class UnifiedEndToEndTests(unittest.TestCase):
    def test_cross_domain_structural_schedules_are_independent(self):
        with tempfile.TemporaryDirectory() as directory:
            outputs={}
            for domain in ("database","telecom"):
                output=Path(directory)/f"{domain}.txt"
                result=subprocess.run([sys.executable,str(ROOT/"generate_dataset.py"),"--domain",domain,"--cases","100","--seed","42","--output",str(output)],text=True,capture_output=True)
                self.assertEqual(result.returncode,0,result.stderr)
                outputs[domain]=output.read_text()
            audit=validate_cross_domain_diversity(outputs["database"],outputs["telecom"])
            self.assertLess(audit["exact_alignment"],.35)

    def test_database_and_telecom_repeated_cli_runs(self):
        with tempfile.TemporaryDirectory() as directory:
            for domain,action_key in (("database","allowed DB actions"),("telecom","allowed telecom actions")):
                for total,seed in ((25,7),(25,42),(100,2026)):
                    with self.subTest(domain=domain,total=total,seed=seed):
                        output=Path(directory)/f"{domain}-{total}-{seed}.txt"
                        result=subprocess.run([sys.executable,str(ROOT/"generate_dataset.py"),"--domain",domain,"--cases",str(total),"--seed",str(seed),"--output",str(output)],text=True,capture_output=True)
                        self.assertEqual(result.returncode,0,result.stderr)
                        validate_serialized_dataset(output.read_text(),action_key,total)
                        self.assertIn("Benign twins:",result.stdout)
                        self.assertIn("Validation: passed",result.stdout)


if __name__=="__main__":unittest.main()
