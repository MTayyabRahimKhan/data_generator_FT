import tempfile
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path

from db_data_generator.generate_dataset import (
    allocate_categories, dataset_cases, generate_cases, public_item,
    plan_dataset_counts, run_generation, serialize_cases, validate_case,
    validate_cases,
)
from security_trace_format import leakage_matches, mission_similarity, validate_serialized_dataset
from security_trace_core import find_evidence_gap_events, find_limit_exceedances, limit_exceedance_indices


class DatabaseGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.counts=plan_dataset_counts(100)
        cls.cases=generate_cases(100,42)
        cls.text=serialize_cases(cls.cases,100)
        cls.documents=validate_serialized_dataset(cls.text,"allowed DB actions",100)

    def test_primary_distribution_and_serialized_twin_count(self):
        self.assertEqual(len(self.cases),self.counts["source_count"])
        self.assertEqual(Counter(c.output.verdict for c in self.cases),Counter({k:v for k,v in self.counts["source_labels"].items() if v}))
        self.assertEqual(len(self.documents),100)
        self.assertEqual(len({d["family_id"] for d in self.documents}),self.counts["source_count"])
        self.assertEqual(len(self.documents)-len(self.cases),self.counts["twin_count"])

    def test_exact_public_keys(self):
        item=public_item(self.cases[0])
        self.assertEqual(list(item),["family_id","MISSION","SCOPE","EVENTS","OUTPUT"])
        self.assertEqual(list(item["SCOPE"]),["allowed reads","allowed writes","allowed DB actions","limits","forbidden"])
        self.assertEqual(list(item["OUTPUT"]),["changed","authorised","first_deviation","contributing_events","label","explanation"])
        forbidden_keys=("CASE_ID:","ENGINE:","DOMAIN:","mission_completed:","verdict:","event_type:","detail:")
        self.assertFalse(any(line.lstrip().startswith(forbidden_keys) for line in self.text.splitlines()))

    def test_true_adjacent_benign_twins(self):
        expanded=dataset_cases(self.cases)
        for index,case in enumerate(expanded):
            if case.output.verdict not in {"suspicious","misaligned","malicious"}:continue
            twin=expanded[index+1]
            self.assertEqual(twin.family_id,case.family_id)
            self.assertTrue(twin.is_twin)
            self.assertEqual(twin.output.verdict,"benign")
            self.assertEqual(twin.mission,case.mission)
            self.assertEqual([(e.event_type,e.target) for e in twin.events],[(e.event_type,e.target) for e in case.events])
            self.assertEqual(twin.output.authorised,"yes")
            self.assertIsNone(twin.output.first_deviation)

    def test_no_label_leakage_and_forbidden_diversity(self):
        for case in dataset_cases(self.cases):
            observed=case.mission+"\n"+"\n".join(f"{e.event_type} {e.target} {e.detail}" for e in case.events)
            self.assertEqual(leakage_matches(observed),[])
        profiles=Counter(tuple(case.scope.forbidden) for case in self.cases)
        self.assertGreaterEqual(len(profiles),3)
        self.assertLessEqual(max(profiles.values())/len(self.cases),.40)

    def test_deviation_positions_cover_all_thirds(self):
        buckets=Counter();definite=[c for c in self.cases if c.output.first_deviation is not None]
        for case in definite:
            ratio=(case.output.first_deviation-2)/max(1,len(case.events)-3)
            buckets["early" if ratio<=1/3 else "middle" if ratio<=2/3 else "late"]+=1
        self.assertTrue(all(buckets[name]/len(definite)>=.25 for name in ("early","middle","late")))

    def test_unrelated_missions_do_not_exceed_ninety_percent(self):
        for index,case in enumerate(self.cases):
            for prior in self.cases[:index]:self.assertLessEqual(mission_similarity(case.mission,prior.mission),.90)

    def test_repeated_seeded_generations_validate(self):
        for seed in (1,7,42,314,2026):
            counts=plan_dataset_counts(25)
            cases=generate_cases(25,seed)
            validate_cases(cases,counts["source_count"],expected_labels=counts["source_labels"])
            validate_serialized_dataset(serialize_cases(cases,25),"allowed DB actions",25)

    def test_semantic_validation_rejects_bad_authorisation(self):
        case=next(c for c in self.cases if c.output.verdict=="malicious")
        with self.assertRaises(ValueError):validate_case(replace(case,output=replace(case.output,authorised="yes")))

    def test_suspicious_records_point_to_scope_limit_evidence(self):
        for case in (case for case in self.cases if case.output.verdict=="suspicious"):
            evidence=find_limit_exceedances(case.events,case.scope.limits,payload_key="detail")
            self.assertEqual(case.scope.limits,{"db.query/customer_records":{"max_rows_scanned":10000}})
            self.assertEqual(case.output.contributing_events,limit_exceedance_indices(evidence))
            self.assertTrue(evidence)
            self.assertIsNone(case.output.first_deviation)
            self.assertIn(f"Events {', '.join(map(str,case.output.contributing_events))}",case.output.explanation)
            self.assertIn(f"max_{evidence[0].metric}={evidence[0].maximum}",case.output.explanation)
            twin=dataset_cases([case])[1]
            self.assertEqual(twin.scope.limits,case.scope.limits)
            self.assertFalse(find_limit_exceedances(twin.events,twin.scope.limits,payload_key="detail"))
            self.assertEqual(twin.output.contributing_events,())

    def test_suspicious_validation_rejects_missing_or_stale_evidence(self):
        case=next(case for case in self.cases if case.output.verdict=="suspicious")
        with self.assertRaises(ValueError):validate_case(replace(case,scope=replace(case.scope,limits={})))
        with self.assertRaises(ValueError):validate_case(replace(case,output=replace(case.output,contributing_events=(1,))))

    def test_serialized_scope_contains_nested_and_empty_limits(self):
        self.assertIn("  limits:\n    db.query/customer_records:\n      max_rows_scanned: 10000",self.text)
        self.assertIn("  limits: {}\n",self.text)

    def test_inconclusive_records_point_to_truncated_evidence(self):
        for case in (case for case in self.cases if case.output.verdict=="inconclusive"):
            gaps=find_evidence_gap_events(case.events,payload_key="detail")
            self.assertTrue(gaps)
            self.assertEqual(case.output.contributing_events,gaps)
            self.assertEqual(case.output.authorised,"undetermined")
            self.assertIsNone(case.output.first_deviation)
            self.assertIn(f"Event {gaps[0]}",case.output.explanation)
            self.assertIn("change_request_fragment",case.output.explanation)

    def test_inconclusive_validation_rejects_missing_or_wrong_gap_evidence(self):
        case=next(case for case in self.cases if case.output.verdict=="inconclusive")
        changed=tuple(replace(event,detail=event.detail.replace(";expected_bytes=4096","")) for event in case.events)
        with self.assertRaises(ValueError):validate_case(replace(case,events=changed))
        with self.assertRaises(ValueError):validate_case(replace(case,output=replace(case.output,contributing_events=(1,))))
        with self.assertRaises(ValueError):validate_case(replace(case,output=replace(case.output,authorised="yes")))

    def test_bulk_500_generation(self):
        cases=generate_cases(500,2026)
        validate_serialized_dataset(serialize_cases(cases,500),"allowed DB actions",500)

    def test_end_to_end_write(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/"database.txt";cases=run_generation(25,output,17)
            self.assertEqual(len(cases),plan_dataset_counts(25)["source_count"])
            validate_serialized_dataset(output.read_text(),"allowed DB actions",25)


if __name__=="__main__":unittest.main()
