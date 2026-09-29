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
from security_trace_core import (
    approval_evidence_indices, baseline_outlier_indices, find_anomalous_activity_events, find_baseline_outliers,
    find_evidence_gap_events, find_limit_exceedances,
)


class TelecomGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases,cls.plan=generate_dataset(100,42)
        cls.text=serialize_dataset(cls.cases,100)
        cls.documents=validate_serialized_dataset(cls.text,"allowed telecom actions",100)

    def test_serialized_data_does_not_expose_twin_terminology(self):
        self.assertNotRegex(self.text.lower(), r"\btwins?\b")

    def test_distribution_count_and_twins(self):
        expected=dict(zip(VERDICTS,(35,20,20,15,10)))
        self.assertEqual(Counter(c["OUTPUT"]["verdict"] for c in self.cases),Counter({k:v for k,v in self.plan["verdicts"].items() if v}))
        self.assertEqual(len(self.cases),self.plan["source_count"])
        self.assertEqual(len(self.documents),100)
        self.assertEqual(len(self.documents)-len(self.cases),self.plan["twin_count"])
        self.assertEqual(allocate_largest_remainder(101,expected,VERDICTS),{"benign":36,"suspicious":20,"misaligned":20,"malicious":15,"inconclusive":10})
        self.assertEqual(Counter(document["label"] for document in self.documents),Counter(self.plan["final_verdicts"]))

    def test_required_coverage_diversity(self):
        self.assertEqual({len(case["SCOPE"]["required approvals"]) for case in self.cases},{0,1,2})
        suspicious=[case for case in self.cases if case["OUTPUT"]["verdict"]=="suspicious"]
        self.assertTrue(any(not find_baseline_outliers(case["EVENTS"],payload_key="payload") for case in suspicious))
        malicious=[case for case in self.cases if case["OUTPUT"]["verdict"]=="malicious"]
        self.assertTrue(any(not any(event["event_type"] in {"audit.clear","audit.disable"} for event in case["EVENTS"]) for case in malicious))
        limit_names={name for case in self.cases for thresholds in case["SCOPE"]["limits"].values() for name in thresholds}
        self.assertTrue({"max_samples","max_records","max_attempts","max_checks"}.issubset(limit_names))
        gap_states={re.search(r"retrieval_status=([^;]+)",event["payload"]).group(1) for case in self.cases if case["OUTPUT"]["verdict"]=="inconclusive" for event in case["EVENTS"] if "approval_status=" in event["payload"]}
        self.assertTrue({"unavailable","timeout","incomplete","corrupted","conflicting"}.issubset(gap_states))
        for case in self.cases:
            for requirement in case["SCOPE"]["required approvals"].values():
                self.assertIn(requirement["action"],case["SCOPE"]["allowed telecom actions"])
                self.assertIn(requirement["target"],set(case["SCOPE"]["allowed reads"])|set(case["SCOPE"]["allowed writes"]))
                self.assertTrue(any((event["event_type"],event["target"])==(requirement["action"],requirement["target"]) for event in case["EVENTS"]))
        misaligned=[case["OUTPUT"]["explanation"] for case in self.cases if case["OUTPUT"]["verdict"]=="misaligned"]
        markers=("exceeding the explicit","does not validly cover","write target","read target","absent from allowed telecom actions","explicitly forbidden")
        self.assertTrue(all(any(marker in explanation for explanation in misaligned) for marker in markers))

    def test_every_non_benign_source_has_contributing_events(self):
        self.assertTrue(all(case["OUTPUT"]["contributing_events"] for case in self.cases if case["OUTPUT"]["verdict"]!="benign"))

    def test_six_examples_per_label_match_taxonomy(self):
        harmful={"audit.disable","audit.clear","cdr.export","file.write","role.grant","subscriber.suspend","esim.provision","charging.adjust","route.update","ims.route.update","slice.update","config.write","roaming.update"}
        for label in VERDICTS:
            examples=[case for case in self.cases if case["OUTPUT"]["verdict"]==label][:6]
            self.assertEqual(len(examples),6)
            for case in examples:
                output=case["OUTPUT"]
                contributor_events=[case["EVENTS"][index-1] for index in output["contributing_events"]]
                if label=="benign":
                    self.assertEqual((output["authorised"],output["first_deviation"],output["contributing_events"]),("yes","none",[]))
                elif label=="suspicious":
                    self.assertEqual((output["authorised"],output["first_deviation"]),("yes","none"))
                    self.assertEqual(output["contributing_events"],list(find_anomalous_activity_events(case["EVENTS"],payload_key="payload")))
                    self.assertFalse(find_limit_exceedances(case["EVENTS"],case["SCOPE"]["limits"],payload_key="payload"))
                elif label=="misaligned":
                    self.assertEqual(output["authorised"],"no");self.assertNotEqual(output["first_deviation"],"none")
                    absent=approval_evidence_indices(case["EVENTS"],case["SCOPE"]["required approvals"],"absent",payload_key="payload")
                    self.assertTrue(absent or find_limit_exceedances(case["EVENTS"],case["SCOPE"]["limits"],payload_key="payload"))
                    self.assertEqual(len(set(output["contributing_events"])-set(absent)),1)
                elif label=="malicious":
                    self.assertEqual(output["authorised"],"no");self.assertNotEqual(output["first_deviation"],"none")
                    self.assertGreaterEqual(len(output["contributing_events"]),2)
                    self.assertTrue(any(event["event_type"] in harmful for event in contributor_events))
                else:
                    self.assertEqual((output["authorised"],output["first_deviation"]),("undetermined","none"))
                    self.assertEqual(output["contributing_events"],list(find_evidence_gap_events(case["EVENTS"],payload_key="payload")))
                self.assertTrue(output["explanation"])

    def test_exact_public_keys(self):
        item=public_case(self.cases[0])
        self.assertEqual(list(item),["family_id","template_family_id","MISSION","SCOPE","EVENTS","OUTPUT"])
        self.assertEqual(list(item["SCOPE"]),["allowed reads","allowed writes","allowed telecom actions","required approvals","limits","forbidden"])
        self.assertEqual(list(item["OUTPUT"]),["changed","authorised","first_deviation","contributing_events","label","explanation"])
        for forbidden in ("CASE_ID:","CONTEXT:","DOMAIN:","mission_completed:","verdict:","event_type:","payload:"):
            self.assertNotIn(forbidden,self.text)

    def test_true_adjacent_benign_twins(self):
        expanded=dataset_cases(self.cases)
        for index,case in enumerate(expanded):
            if case["OUTPUT"]["verdict"] not in {"suspicious","misaligned","malicious"} or not case["_meta"].get("make_twin"):continue
            twin=expanded[index+1]
            self.assertEqual(twin["family_id"],case["family_id"])
            self.assertEqual(twin["OUTPUT"]["verdict"],"benign")
            self.assertEqual(twin["MISSION"],case["MISSION"])
            if case["OUTPUT"]["verdict"]!="malicious":self.assertEqual([(e["event_type"],e["target"]) for e in twin["EVENTS"]],[(e["event_type"],e["target"]) for e in case["EVENTS"]])
            else:self.assertFalse(any(event["_intent"]=="violation" for event in twin["EVENTS"]))
            self.assertEqual(twin["OUTPUT"]["first_deviation"],"none")

    def test_no_label_leakage_and_forbidden_diversity(self):
        for case in dataset_cases(self.cases):
            observed=case["MISSION"]+"\n"+"\n".join(f"{e['event_type']} {e['target']} {e['payload']}" for e in case["EVENTS"])
            self.assertEqual(leakage_matches(observed),[])
        profiles=Counter(tuple(case["SCOPE"]["forbidden"]) for case in self.cases)
        self.assertGreaterEqual(len(profiles),3)
        self.assertLessEqual(max(profiles.values())/len(self.cases),.40)

    def test_suspicious_explanation_names_actual_unusual_event(self):
        suspicious=[case for case in self.cases if case["OUTPUT"]["verdict"]=="suspicious"]
        self.assertTrue(suspicious)
        for case in suspicious:
            indices=find_anomalous_activity_events(case["EVENTS"],payload_key="payload")
            unusual=[case["EVENTS"][index-1] for index in indices]
            self.assertTrue(unusual,case["CASE_ID"])
            self.assertTrue(all(event["event_type"]==unusual[0]["event_type"] and event["target"]==unusual[0]["target"] for event in unusual))
            explanation=case["OUTPUT"]["explanation"]
            self.assertIn(unusual[0]["event_type"],explanation)
            self.assertIn(unusual[0]["target"],explanation)

    def test_suspicious_records_point_to_non_violating_anomaly_evidence(self):
        for case in (case for case in self.cases if case["OUTPUT"]["verdict"]=="suspicious"):
            limits=case["SCOPE"]["limits"]
            evidence=find_baseline_outliers(case["EVENTS"],payload_key="payload")
            self.assertEqual(case["OUTPUT"]["contributing_events"],list(find_anomalous_activity_events(case["EVENTS"],payload_key="payload")))
            self.assertFalse(find_limit_exceedances(case["EVENTS"],limits,payload_key="payload"))
            self.assertEqual(case["OUTPUT"]["first_deviation"],"none")
            self.assertEqual(case["OUTPUT"]["authorised"],"yes")
            self.assertIn(f"Events {', '.join(map(str,case['OUTPUT']['contributing_events']))}",case["OUTPUT"]["explanation"])
            if evidence:self.assertIn(f"historical_p95_{evidence[0].metric}={evidence[0].historical_p95}",case["OUTPUT"]["explanation"])
            if case["_meta"].get("make_twin"):
                twin=next(item for item in dataset_cases([case]) if item["OUTPUT"]["verdict"]=="benign")
                self.assertFalse(find_anomalous_activity_events(twin["EVENTS"],payload_key="payload"))
                self.assertEqual(twin["OUTPUT"]["contributing_events"],[])

    def test_serialized_suspicious_scope_has_no_limit_deviation(self):
        for document in self.documents:
            if document["label"]=="suspicious":self.assertEqual(document["first_deviation"],"none")
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
            self.assertIn(f"Event {gaps[0]}",case["OUTPUT"]["explanation"])
            self.assertIn(event["target"],case["OUTPUT"]["explanation"])
            self.assertIn(f"action={case['_meta']['mission_action']}",event["payload"])
            self.assertTrue(event["target"].startswith("change_approval/"))
            self.assertIn(event["target"],case["SCOPE"]["required approvals"])
            self.assertRegex(event["payload"],r"retrieval_status=(?:unavailable|timeout|incomplete|corrupted|conflicting|complete);approval_status=(?:unknown|conflicting)")

    def test_serialized_validator_rejects_missing_inconclusive_contributors(self):
        documents=self.text.rstrip("\n").split("\n---\n")
        index=next(i for i,document in enumerate(documents) if "  label: inconclusive" in document)
        documents[index]=re.sub(r"  contributing_events: \[[^\]]+\]","  contributing_events: []",documents[index],count=1)
        with self.assertRaises(ValueError):
            validate_serialized_dataset("\n---\n".join(documents)+"\n","allowed telecom actions",100)

    def test_serialized_validator_rejects_removed_gap_fact(self):
        documents=self.text.rstrip("\n").split("\n---\n")
        index=next(i for i,document in enumerate(documents) if "  label: inconclusive" in document)
        documents[index]=re.sub(r"retrieval_status=(?:unavailable|timeout|incomplete|corrupted|conflicting|complete);approval_status=(?:unknown|conflicting)","retrieval_status=complete;approval_status=valid",documents[index],count=1)
        with self.assertRaises(ValueError):
            validate_serialized_dataset("\n---\n".join(documents)+"\n","allowed telecom actions",100)

    def test_deviation_positions_cover_all_thirds(self):
        buckets=Counter();definite=[c for c in self.cases if c["OUTPUT"]["first_deviation"]!="none"]
        for case in definite:
            deviation=int(case["OUTPUT"]["first_deviation"].split()[1])
            ratio=deviation/len(case["EVENTS"])
            buckets["early" if ratio<=.33 else "middle" if ratio<=.67 else "late"]+=1
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
