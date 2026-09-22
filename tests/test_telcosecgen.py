from __future__ import annotations

import subprocess
import sys
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from security_trace_format import leakage_matches, mission_similarity, validate_serialized_dataset
from telcosecgen.engine import (
    VERDICTS, allocate_largest_remainder, dataset_cases, generate_dataset,
    load_config, public_case, serialize_dataset, validate_dataset,
)


class TelecomGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases,cls.plan=generate_dataset(100,42)
        cls.text=serialize_dataset(cls.cases,100)
        cls.documents=validate_serialized_dataset(cls.text,"allowed telecom actions",100)

    def test_distribution_count_and_twins(self):
        expected=dict(zip(VERDICTS,(35,20,20,15,10)))
        self.assertEqual(Counter(c["OUTPUT"]["verdict"] for c in self.cases),Counter({k:v for k,v in self.plan["verdicts"].items() if v}))
        self.assertEqual(len(self.cases),self.plan["source_count"])
        self.assertEqual(len(self.documents),100)
        self.assertEqual(len(self.documents)-len(self.cases),self.plan["twin_count"])
        self.assertEqual(allocate_largest_remainder(101,expected,VERDICTS),{"benign":36,"suspicious":20,"misaligned":20,"malicious":15,"inconclusive":10})

    def test_exact_public_keys(self):
        item=public_case(self.cases[0])
        self.assertEqual(list(item),["family_id","MISSION","SCOPE","EVENTS","OUTPUT"])
        self.assertEqual(list(item["SCOPE"]),["allowed reads","allowed writes","allowed telecom actions","forbidden"])
        self.assertEqual(list(item["OUTPUT"]),["changed","authorised","first_deviation","contributing_events","label","explanation"])
        for forbidden in ("CASE_ID:","CONTEXT:","DOMAIN:","mission_completed:","verdict:","event_type:","payload:"):
            self.assertNotIn(forbidden,self.text)

    def test_true_adjacent_benign_twins(self):
        expanded=dataset_cases(self.cases)
        for index,case in enumerate(expanded):
            if case["OUTPUT"]["verdict"] not in {"suspicious","misaligned","malicious"}:continue
            twin=expanded[index+1]
            self.assertEqual(twin["family_id"],case["family_id"])
            self.assertEqual(twin["OUTPUT"]["verdict"],"benign")
            self.assertEqual(twin["MISSION"],case["MISSION"])
            self.assertEqual([(e["event_type"],e["target"]) for e in twin["EVENTS"]],[(e["event_type"],e["target"]) for e in case["EVENTS"]])
            self.assertEqual(twin["OUTPUT"]["first_deviation"],"none")

    def test_no_label_leakage_and_forbidden_diversity(self):
        for case in dataset_cases(self.cases):
            observed=case["MISSION"]+"\n"+"\n".join(f"{e['event_type']} {e['target']} {e['payload']}" for e in case["EVENTS"])
            self.assertEqual(leakage_matches(observed),[])
        profiles=Counter(tuple(case["SCOPE"]["forbidden"]) for case in self.cases)
        self.assertGreaterEqual(len(profiles),3)
        self.assertLessEqual(max(profiles.values())/len(self.cases),.40)

    def test_suspicious_explanation_names_actual_unusual_event(self):
        markers=("records=48000","objects=12500","attempts=7","checks=9","samples=86400","records=32000","checks=12","records=22000")
        suspicious=[case for case in self.cases if case["OUTPUT"]["verdict"]=="suspicious"]
        self.assertTrue(suspicious)
        for case in suspicious:
            unusual=[event for event in case["EVENTS"] if any(marker in event["payload"] for marker in markers)]
            self.assertTrue(unusual,case["CASE_ID"])
            self.assertTrue(all(event["event_type"]==unusual[0]["event_type"] and event["target"]==unusual[0]["target"] for event in unusual))
            explanation=case["OUTPUT"]["explanation"]
            self.assertIn(unusual[0]["event_type"],explanation)
            self.assertIn(unusual[0]["target"],explanation)

    def test_deviation_positions_cover_all_thirds(self):
        buckets=Counter();definite=[c for c in self.cases if c["OUTPUT"]["first_deviation"]!="none"]
        for case in definite:
            deviation=int(case["OUTPUT"]["first_deviation"].split()[1])
            ratio=(deviation-2)/max(1,len(case["EVENTS"])-3)
            buckets["early" if ratio<=1/3 else "middle" if ratio<=2/3 else "late"]+=1
        self.assertTrue(all(buckets[name]/len(definite)>=.25 for name in ("early","middle","late")))

    def test_mission_similarity(self):
        for index,case in enumerate(self.cases):
            for prior in self.cases[:index]:self.assertLessEqual(mission_similarity(case["MISSION"],prior["MISSION"]),.90)

    def test_repeated_seeded_generations(self):
        for seed in (1,7,42,314,2026):
            cases,plan=generate_dataset(25,seed)
            self.assertEqual(validate_dataset(cases,plan["source_count"],load_config(),expected_verdicts=plan["verdicts"]),[])
            validate_serialized_dataset(serialize_dataset(cases,25),"allowed telecom actions",25)

    def test_package_cli(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/"telecom.txt"
            result=subprocess.run([sys.executable,"-m","telcosecgen","generate","--cases","25","--output",str(output),"--seed","7"],text=True,capture_output=True)
            self.assertEqual(result.returncode,0,result.stderr)
            validate_serialized_dataset(output.read_text(),"allowed telecom actions",25)


if __name__=="__main__":unittest.main()
