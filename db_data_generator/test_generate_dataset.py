import tempfile
import unittest
from collections import Counter
from dataclasses import replace
from pathlib import Path

from db_data_generator.generate_dataset import (
    allocate_categories, dataset_cases, generate_cases, public_item,
    run_generation, serialize_cases, validate_case, validate_cases,
)
from security_trace_format import leakage_matches, mission_similarity, validate_serialized_dataset


class DatabaseGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.cases=generate_cases(100,42)
        cls.text=serialize_cases(cls.cases)
        cls.documents=validate_serialized_dataset(cls.text,"allowed DB actions",100)

    def test_primary_distribution_and_serialized_twin_count(self):
        self.assertEqual(len(self.cases),100)
        self.assertEqual(Counter(c.output.verdict for c in self.cases),Counter(allocate_categories(100)))
        self.assertEqual(len(self.documents),155)
        self.assertEqual(len({d["family_id"] for d in self.documents}),100)

    def test_exact_public_keys(self):
        item=public_item(self.cases[0])
        self.assertEqual(list(item),["family_id","MISSION","SCOPE","EVENTS","OUTPUT"])
        self.assertEqual(list(item["SCOPE"]),["allowed reads","allowed writes","allowed DB actions","forbidden"])
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
            cases=generate_cases(25,seed)
            validate_cases(cases,25)
            validate_serialized_dataset(serialize_cases(cases),"allowed DB actions",25)

    def test_semantic_validation_rejects_bad_authorisation(self):
        case=next(c for c in self.cases if c.output.verdict=="malicious")
        with self.assertRaises(ValueError):validate_case(replace(case,output=replace(case.output,authorised="yes")))

    def test_bulk_500_generation(self):
        cases=generate_cases(500,2026)
        validate_serialized_dataset(serialize_cases(cases),"allowed DB actions",500)

    def test_end_to_end_write(self):
        with tempfile.TemporaryDirectory() as directory:
            output=Path(directory)/"database.txt";cases=run_generation(25,output,17)
            self.assertEqual(len(cases),25)
            validate_serialized_dataset(output.read_text(),"allowed DB actions",25)


if __name__=="__main__":unittest.main()
