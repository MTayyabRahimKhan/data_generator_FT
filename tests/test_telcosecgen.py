from __future__ import annotations

import re
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
from security_trace_core import find_evidence_gap_events, find_limit_exceedances, limit_exceedance_indices


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
        self.assertEqual(list(item["SCOPE"]),["allowed reads","allowed writes","allowed telecom actions","limits","forbidden"])
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

    def test_suspicious_records_point_to_scope_limit_evidence(self):
        for case in (case for case in self.cases if case["OUTPUT"]["verdict"]=="suspicious"):
            limits=case["SCOPE"]["limits"]
            evidence=find_limit_exceedances(case["EVENTS"],limits,payload_key="payload")
            self.assertTrue(limits)
            self.assertTrue(evidence)
            self.assertEqual(case["OUTPUT"]["contributing_events"],list(limit_exceedance_indices(evidence)))
            self.assertEqual(case["OUTPUT"]["first_deviation"],"none")
            self.assertEqual(case["OUTPUT"]["authorised"],"yes")
            self.assertIn(f"Events {', '.join(map(str,case['OUTPUT']['contributing_events']))}",case["OUTPUT"]["explanation"])
            self.assertIn(f"max_{evidence[0].metric}={evidence[0].maximum}",case["OUTPUT"]["explanation"])
            twin=next(item for item in dataset_cases([case]) if item["OUTPUT"]["verdict"]=="benign")
            self.assertEqual(twin["SCOPE"]["limits"],limits)
            self.assertFalse(find_limit_exceedances(twin["EVENTS"],twin["SCOPE"]["limits"],payload_key="payload"))
            self.assertEqual(twin["OUTPUT"]["contributing_events"],[])

    def test_serialized_scope_contains_nested_and_empty_limits(self):
        self.assertIn("  limits:\n    ",self.text)
        self.assertIn("  limits: {}\n",self.text)

    def test_serialized_validator_rejects_missing_suspicious_contributors(self):
        documents=self.text.rstrip("\n").split("\n---\n")
        index=next(i for i,document in enumerate(documents) if "  label: suspicious" in document)
        documents[index]=re.sub(r"  contributing_events: \[[^\]]+\]","  contributing_events: []",documents[index],count=1)
        with self.assertRaises(ValueError):
            validate_serialized_dataset("\n---\n".join(documents)+"\n","allowed telecom actions",100)

    def test_inconclusive_records_point_to_evidence_gap_events(self):
        for case in (case for case in self.cases if case["OUTPUT"]["verdict"]=="inconclusive"):
            gaps=find_evidence_gap_events(case["EVENTS"],payload_key="payload")
            self.assertTrue(gaps)
            self.assertEqual(case["OUTPUT"]["contributing_events"],list(gaps))
            self.assertEqual(case["OUTPUT"]["authorised"],"undetermined")
            self.assertEqual(case["OUTPUT"]["first_deviation"],"none")
            event=case["EVENTS"][gaps[0]-1]
            self.assertIn(f"event {gaps[0]}",case["OUTPUT"]["explanation"])
            self.assertIn(event["target"],case["OUTPUT"]["explanation"])

    def test_serialized_validator_rejects_missing_inconclusive_contributors(self):
        documents=self.text.rstrip("\n").split("\n---\n")
        index=next(i for i,document in enumerate(documents) if "  label: inconclusive" in document)
        documents[index]=re.sub(r"  contributing_events: \[[^\]]+\]","  contributing_events: []",documents[index],count=1)
        with self.assertRaises(ValueError):
            validate_serialized_dataset("\n---\n".join(documents)+"\n","allowed telecom actions",100)

    def test_serialized_validator_rejects_removed_gap_fact(self):
        documents=self.text.rstrip("\n").split("\n---\n")
        index=next(i for i,document in enumerate(documents) if "  label: inconclusive" in document and "lookup_result=not_found" in document)
        documents[index]=documents[index].replace("lookup_result=not_found","lookup_result=found",1)
        with self.assertRaises(ValueError):
            validate_serialized_dataset("\n---\n".join(documents)+"\n","allowed telecom actions",100)

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
