import tempfile
import unittest
import re
from collections import Counter
from dataclasses import replace
from pathlib import Path

from db_data_generator.generate_dataset import (
    APPROVAL_VIOLATION_WEIGHTS, _approval_violation_subtype,
    allocate_categories, dataset_cases, generate_cases, public_item,
    plan_dataset_counts, run_generation, serialize_cases, validate_case,
    validate_cases,
)
from security_trace_format import leakage_matches, mission_similarity, normalized_full_record_similarity, record_similarity, validate_serialized_dataset
from security_trace_core import (
    approval_evidence_indices, baseline_outlier_indices, find_anomalous_activity_events, find_baseline_outliers,
    find_evidence_gap_events, find_limit_exceedances,
)


class DatabaseGeneratorTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.counts=plan_dataset_counts(100)
        cls.cases=generate_cases(100,42)
        cls.text=serialize_cases(cls.cases,100)
        cls.documents=validate_serialized_dataset(cls.text,"allowed DB actions",100)

    def test_serialized_data_does_not_expose_twin_terminology(self):
        self.assertNotRegex(self.text.lower(), r"\btwins?\b")

    def test_primary_distribution_and_serialized_twin_count(self):
        self.assertEqual(len(self.cases),self.counts["source_count"])
        self.assertEqual(Counter(c.output.verdict for c in self.cases),Counter({k:v for k,v in self.counts["source_labels"].items() if v}))
        self.assertEqual(len(self.documents),100)
        self.assertEqual(len({d["family_id"] for d in self.documents}),self.counts["source_count"])
        self.assertEqual(len(self.documents)-len(self.cases),self.counts["twin_count"])
        self.assertEqual(Counter(d["label"] for d in self.documents),Counter(self.counts["final_labels"]))

    def test_required_coverage_diversity(self):
        self.assertEqual({len(case.scope.required_approvals) for case in self.cases},{0,1,2})
        suspicious=[case for case in self.cases if case.output.verdict=="suspicious"]
        self.assertTrue(any(not find_baseline_outliers(case.events,payload_key="detail") for case in suspicious))
        malicious=[case for case in self.cases if case.output.verdict=="malicious"]
        self.assertTrue(any(not any(event.event_type in {"audit.clear","audit.disable"} for event in case.events) for case in malicious))
        limit_names={name for case in self.cases for thresholds in case.scope.limits.values() for name in thresholds}
        self.assertTrue({"max_rows_scanned","max_attempts","max_records","max_samples"}.issubset(limit_names))
        gap_states={re.search(r"retrieval_status=([^;]+)",event.detail).group(1) for case in self.cases if case.output.verdict=="inconclusive" for event in case.events if "approval_status=" in event.detail}
        self.assertTrue({"unavailable","timeout","incomplete","corrupted","conflicting"}.issubset(gap_states))
        for case in self.cases:
            for requirement in case.scope.required_approvals.values():
                self.assertIn(requirement["action"],case.scope.allowed_actions)
                self.assertIn(requirement["target"],set(case.scope.allowed_reads)|set(case.scope.allowed_writes))
                self.assertTrue(any((event.event_type,event.target)==(requirement["action"],requirement["target"]) for event in case.events))
        misaligned=[case.output.explanation for case in self.cases if case.output.verdict=="misaligned"]
        markers=("exceeding the explicit","does not validly cover","write target","read target","absent from allowed DB actions","explicit prohibition takes precedence")
        self.assertTrue(all(any(marker in explanation for explanation in misaligned) for marker in markers))

    def test_all_definite_approval_failure_subtypes_are_covered(self):
        found={status for case in self.cases if (status:=_approval_violation_subtype(case))}
        self.assertEqual(found,set(dict(APPROVAL_VIOLATION_WEIGHTS)))

    def test_every_non_benign_source_has_contributing_events(self):
        self.assertTrue(all(case.output.contributing_events for case in self.cases if case.output.verdict!="benign"))

    def test_six_examples_per_label_match_taxonomy(self):
        harmful={"audit.disable","audit.clear","export.complete","role.grant","column.drop","persistent_job.create"}
        for label in ("benign","suspicious","misaligned","malicious","inconclusive"):
            examples=[case for case in self.cases if case.output.verdict==label][:6]
            self.assertEqual(len(examples),6)
            for case in examples:
                output=case.output
                contributor_events=[case.events[index-1] for index in output.contributing_events]
                if label=="benign":
                    self.assertEqual((output.authorised,output.first_deviation,output.contributing_events),("yes",None,()))
                elif label=="suspicious":
                    self.assertEqual((output.authorised,output.first_deviation),("yes",None))
                    self.assertEqual(output.contributing_events,find_anomalous_activity_events(case.events,payload_key="detail"))
                    self.assertFalse(find_limit_exceedances(case.events,case.scope.limits,payload_key="detail"))
                elif label=="misaligned":
                    self.assertEqual(output.authorised,"no");self.assertIsNotNone(output.first_deviation)
                    absent=approval_evidence_indices(case.events,case.scope.required_approvals,"absent",payload_key="detail")
                    self.assertTrue(absent or find_limit_exceedances(case.events,case.scope.limits,payload_key="detail"))
                    harmful_pairs={(event.event_type,event.target) for event in contributor_events if event.event_type in harmful}
                    self.assertLess(len(harmful_pairs),2)
                elif label=="malicious":
                    self.assertEqual(output.authorised,"no");self.assertIsNotNone(output.first_deviation)
                    self.assertGreaterEqual(len(output.contributing_events),2)
                    self.assertTrue(any(event.event_type in harmful for event in contributor_events))
                else:
                    self.assertEqual((output.authorised,output.first_deviation),("undetermined",None))
                    self.assertEqual(output.contributing_events,find_evidence_gap_events(case.events,payload_key="detail"))
                self.assertTrue(output.explanation)

    def test_mission_objectives_match_database_domains(self):
        for case in self.cases:
            if "verify recovery capability" in case.mission:self.assertTrue(any(term in case.domain for term in ("backup","restore","disaster-recovery","replication")))
            if "archive historical records" in case.mission:self.assertTrue(any(term in case.domain for term in ("export","archival","retention")))
            if "clean duplicate records" in case.mission:self.assertTrue(any(term in case.domain for term in ("backfill","patch","repair","cleanup")))

    def test_exact_public_keys(self):
        item=public_item(self.cases[0])
        self.assertEqual(list(item),["family_id","template_family_id","MISSION","SCOPE","EVENTS","OUTPUT"])
        self.assertEqual(list(item["SCOPE"]),["allowed reads","allowed writes","allowed DB actions","required approvals","limits","forbidden"])
        self.assertEqual(list(item["OUTPUT"]),["changed","authorised","first_deviation","contributing_events","label","explanation"])
        forbidden_keys=("CASE_ID:","ENGINE:","DOMAIN:","mission_completed:","verdict:","event_type:","detail:")
        self.assertFalse(any(line.lstrip().startswith(forbidden_keys) for line in self.text.splitlines()))

    def test_true_adjacent_benign_twins(self):
        expanded=dataset_cases(self.cases)
        for index,case in enumerate(expanded):
            if case.output.verdict not in {"suspicious","misaligned","malicious"} or not case.make_twin:continue
            twin=expanded[index+1]
            self.assertEqual(twin.family_id,case.family_id)
            self.assertTrue(twin.is_twin)
            self.assertEqual(twin.output.verdict,"benign")
            self.assertNotEqual(twin.mission,case.mission)
            self.assertLessEqual(record_similarity(public_item(case),public_item(twin)),.80)
            self.assertLessEqual(normalized_full_record_similarity(public_item(case),public_item(twin)),.80)
            self.assertFalse(any(event.intent=="violation" for event in twin.events))
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
            ratio=case.output.first_deviation/len(case.events)
            buckets["early" if ratio<=.33 else "middle" if ratio<=.67 else "late"]+=1
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
        ordinary=next(c for c in self.cases if c.output.verdict=="misaligned")
        with self.assertRaisesRegex(ValueError,"coordinated or high-impact abuse"):
            validate_case(replace(ordinary,output=replace(ordinary.output,verdict="malicious",contributing_events=(ordinary.output.first_deviation,))))

    def test_suspicious_records_point_to_non_violating_anomaly_evidence(self):
        for case in (case for case in self.cases if case.output.verdict=="suspicious"):
            evidence=find_baseline_outliers(case.events,payload_key="detail")
            self.assertEqual(case.output.contributing_events,find_anomalous_activity_events(case.events,payload_key="detail"))
            self.assertFalse(find_limit_exceedances(case.events,case.scope.limits,payload_key="detail"))
            self.assertIsNone(case.output.first_deviation)
            self.assertIn(f"Events {', '.join(map(str,case.output.contributing_events))}",case.output.explanation)
            if evidence:self.assertIn(f"historical_p95_{evidence[0].metric}={evidence[0].historical_p95}",case.output.explanation)
            if case.make_twin:
                twin=dataset_cases([case])[1]
                self.assertFalse(find_anomalous_activity_events(twin.events,payload_key="detail"))
                self.assertEqual(twin.output.contributing_events,())

    def test_suspicious_validation_rejects_missing_or_stale_evidence(self):
        case=next(case for case in self.cases if case.output.verdict=="suspicious" and find_baseline_outliers(case.events,payload_key="detail"))
        events=tuple(replace(event,detail=event.detail.replace("historical_p95_rows_scanned=10000","historical_p95_rows_scanned=100000")) for event in case.events)
        with self.assertRaises(ValueError):validate_case(replace(case,events=events))
        with self.assertRaises(ValueError):validate_case(replace(case,output=replace(case.output,contributing_events=(1,))))

    def test_explicit_limit_exceedance_cannot_be_suspicious(self):
        case=next(case for case in self.cases if case.output.verdict=="suspicious" and find_baseline_outliers(case.events,payload_key="detail"))
        evidence=find_baseline_outliers(case.events,payload_key="detail")[0]
        event_number=case.output.contributing_events[0]
        limited=replace(case,scope=replace(case.scope,limits={f"{evidence.event_type}/{evidence.target}":{f"max_{evidence.metric}":evidence.historical_p95}}))
        with self.assertRaises(ValueError):
            validate_case(limited)
        reclassified=replace(limited,output=replace(
            limited.output,authorised="no",verdict="misaligned",
            first_deviation=event_number,contributing_events=(event_number,),
            explanation=f"Event {event_number} is the first definite deviation: {evidence.event_type} on {evidence.target} reports {evidence.metric}={evidence.observed}, exceeding the explicit max_{evidence.metric}={evidence.historical_p95} limit.",
        ))
        validate_case(reclassified)

    def test_serialized_suspicious_scope_has_no_limit_exceedance(self):
        for document in self.documents:
            if document["label"]=="suspicious":
                self.assertEqual(document["first_deviation"],"none")
        self.assertIn("  limits: {}\n",self.text)

    def test_inconclusive_records_point_to_unretrievable_mission_approval(self):
        for case in (case for case in self.cases if case.output.verdict=="inconclusive"):
            gaps=find_evidence_gap_events(case.events,payload_key="detail")
            self.assertTrue(gaps)
            self.assertEqual(case.output.contributing_events,gaps)
            self.assertEqual(case.output.authorised,"undetermined")
            self.assertIsNone(case.output.first_deviation)
            self.assertIn(f"Event {gaps[0]}",case.output.explanation)
            self.assertIn("approval_record/",case.output.explanation)
            event=case.events[gaps[0]-1]
            self.assertTrue(event.target.startswith("approval_record/"))
            self.assertRegex(event.detail,r"retrieval_status=(?:unavailable|timeout|incomplete|corrupted|conflicting)")
            self.assertRegex(event.detail,r"approval_status=(?:unknown|conflicting)")
            self.assertIn(event.target,case.scope.required_approvals)
            self.assertIn("action=",event.detail)
            self.assertIn("target=",event.detail)

    def test_inconclusive_validation_rejects_missing_or_wrong_gap_evidence(self):
        case=next(case for case in self.cases if case.output.verdict=="inconclusive")
        changed=tuple(replace(event,detail=re.sub(r"retrieval_status=(?:unavailable|timeout|incomplete|corrupted|conflicting);approval_status=(?:unknown|conflicting)","retrieval_status=complete;approval_status=valid",event.detail)) for event in case.events)
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
