"""Preflight regression tests, not cryptographic backend acceptance tests."""
import copy
import json
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import preflight as p

sys.dont_write_bytecode = True
sys.path[:0] = [str(p.DEFAULT_REPO / "src"), str(p.DEFAULT_REPO)]
from ibme.hibe.abb10 import ABB10HIBE
from ibme.hibe.mock import MockHIBE


class UnknownBackend:
    security_claim = "none"
    backend_admitted = True  # Deliberately lying: this must not authorize it.
    def setup(self, params, *, rng=None): raise AssertionError("must not execute")
    def extract(self, msk, parent_id, *, rng=None): raise AssertionError("must not execute")
    def derive(self, sk_parent, child_id, *, rng=None): raise AssertionError("must not execute")
    def encrypt(self, pk, parent_id, child_id, payload, *, rng=None): raise AssertionError("must not execute")
    def decrypt(self, sk_child, ct, *, rng=None): raise AssertionError("must not execute")
    def load_ciphertext(self, data): raise AssertionError("must not execute")
    def validate_key_binding(self, public_key, secret_key): return True


class InnocentlyNamed(ABB10HIBE):
    backend_admitted = True


class ContractTests(unittest.TestCase):
    def test_exact_contract(self):
        self.assertEqual(p.contract_problems(copy.deepcopy(p.CONTRACT)), [])

    def test_same_leaf_capacity_not_identity_sum(self):
        value = dict(p.CONTRACT, same_leaf_target_capacity=32)
        self.assertIn("CONTRACT_MISMATCH:same_leaf_target_capacity", p.contract_problems(value))

    def test_eight_identity_shards_rejected(self):
        self.assertIn("CONTRACT_MISMATCH:identity_sharding", p.contract_problems(dict(p.CONTRACT, identity_sharding=True)))

    def test_repeated_preimage_rejected(self):
        self.assertTrue(p.contract_problems(dict(p.CONTRACT, preimage_sampling="repeat-one-preimage-256-times")))

    def test_reversed_roles_rejected(self):
        self.assertEqual(len(p.contract_problems(dict(p.CONTRACT, parent_role="phi", child_role="rcv"))), 2)

    def test_wrong_input_lengths(self):
        for field, length in (("parent_bytes", 64), ("child_bytes", 64), ("seed_bytes", 216), ("seed_bytes", 31)):
            with self.subTest(field=field, length=length):
                self.assertTrue(p.contract_problems(dict(p.CONTRACT, **{field: length})))

    def test_booleans_are_not_numeric_capacities(self):
        for field in ("same_leaf_target_capacity", "parent_bytes", "seed_bytes"):
            self.assertTrue(p.contract_problems(dict(p.CONTRACT, **{field: True})))

    def test_positions_must_cover_zero_to_255(self):
        self.assertTrue(p.contract_problems(dict(p.CONTRACT, position_range=[1, 256])))
        self.assertTrue(p.contract_problems(dict(p.CONTRACT, position_range=[False, 255])))

    def test_other_family_and_fixture_rejected(self):
        self.assertTrue(p.contract_problems(dict(p.CONTRACT, family="ABB10")))
        self.assertTrue(p.contract_problems(dict(p.CONTRACT, implementation_kind="public-fixture")))

    def test_missing_and_extra_evidence_rejected(self):
        self.assertTrue(p.contract_problems({}))
        self.assertTrue(p.contract_problems(dict(p.CONTRACT, backend_admitted=True)))

    def test_no_security_admission_even_when_functionally_ready(self):
        # A decision-unit test only, NOT evidence of an existing backend.
        verdict = p.functional_verdict([])
        self.assertTrue(verdict["ready_for_bounded_smoke"])
        self.assertEqual(verdict["security_claim"], "none")
        self.assertFalse(verdict["backend_admitted"])
        self.assertFalse(verdict["functional_integration_passed"])
        self.assertFalse(verdict["smoke_executed"])

    def test_failure_nonzero_and_first_blocker_preserved(self):
        verdict = p.functional_verdict(["FIRST", "SECOND"])
        self.assertEqual(verdict["first_blocker"], "FIRST")
        self.assertEqual(verdict["exit_code"], 2)
        self.assertFalse(verdict["ready_for_bounded_smoke"])


class BackendGuards(unittest.TestCase):
    def test_actual_abb10_rejected(self):
        self.assertIn("MOCK_OR_TEACHING_BACKEND", p.backend_problems(ABB10HIBE(), p.DEFAULT_REPO))

    def test_actual_mock_rejected(self):
        self.assertIn("MOCK_OR_TEACHING_BACKEND", p.backend_problems(MockHIBE(), p.DEFAULT_REPO))

    def test_renamed_teaching_subclass_rejected(self):
        self.assertIn("MOCK_OR_TEACHING_BACKEND", p.backend_problems(InnocentlyNamed(), p.DEFAULT_REPO))

    def test_unknown_complete_interface_with_true_flag_rejected(self):
        reasons = p.backend_problems(UnknownBackend(), p.DEFAULT_REPO)
        self.assertIn("NOT_THE_REVIEWED_CHKP_SLOT", reasons)
        self.assertTrue(any(reason.startswith("UNREVIEWED_METHOD_ORIGIN:") for reason in reasons))

    def test_empty_backend_rejected(self):
        self.assertTrue(p.backend_problems(object(), p.DEFAULT_REPO))

    def test_monkeypatched_method_rejected(self):
        backend = UnknownBackend()
        backend.encrypt = lambda *args, **kwargs: None
        self.assertIn("MISSING_OR_REPLACED_PUBLIC_METHOD:encrypt", p.backend_problems(backend, p.DEFAULT_REPO))


class InventoryAndLineage(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.current = p.check(p.DEFAULT_REPO)

    def test_actual_first_blocker_is_missing_slot(self):
        self.assertEqual(self.current["git_head"], p.EXPECTED_HEAD)
        self.assertEqual(self.current["first_blocker"], "CHKP_PUBLIC_BACKEND_MISSING")
        self.assertFalse(self.current["ready_for_bounded_smoke"])

    def test_actual_inventory_distinguishes_components(self):
        inventory = self.current["inventory"]
        self.assertEqual({path for path in inventory if path.startswith("src/ibme/hibe/")},
                         {"src/ibme/hibe/" + name for name in ("__init__.py", "api.py", "abb10.py", "mock.py")})
        funcs = inventory["experiments/research/first_suite/seed_kem.py"]["functions"]
        self.assertIn("encapsulate_seed", [f["name"] for f in funcs])
        self.assertNotIn("setup", [f["name"] for f in funcs])

    def test_head_mismatch_precedes_backend_selection(self):
        result = p.check(p.DEFAULT_REPO, expected_head="0" * 40)
        self.assertEqual(result["first_blocker"], "REPOSITORY_HEAD_MISMATCH")

    def test_duplicate_review_fields_rejected(self):
        with self.assertRaises(ValueError):
            json.loads('{"schema":1,"schema":2}', object_pairs_hook=p.reject_duplicate_keys)

    def test_parallel_changes_are_recorded_not_treated_as_backend(self):
        with patch.object(p, "git", side_effect=[p.EXPECTED_HEAD, "?? unrelated_parallel_work.py"]):
            result = p.check(p.DEFAULT_REPO)
        self.assertEqual(result["git_status"], "?? unrelated_parallel_work.py")
        self.assertEqual(result["first_blocker"], "CHKP_PUBLIC_BACKEND_MISSING")

    def test_slot_presence_alone_never_imports_or_admits(self):
        with tempfile.TemporaryDirectory(prefix="slot-test-", dir=Path(__file__).parent) as name:
            repo = Path(name)
            slot = repo / p.SLOT
            slot.parent.mkdir(parents=True)
            slot.write_text('raise RuntimeError("UNREVIEWED_IMPORT_MUST_NOT_RUN")\n', encoding="utf-8")
            with patch.object(p, "git", side_effect=[p.EXPECTED_HEAD, ""]), patch.object(p, "source_snapshot", return_value={"sha256": "x", "files": {}}):
                result = p.check(repo)
            self.assertEqual(result["first_blocker"], "CHKP_FUNCTIONAL_SOURCE_REVIEW_REQUIRED")
            self.assertFalse(result["backend_admitted"])

    def test_direct_teaching_alias_in_chkp_slot_rejected_before_import(self):
        with tempfile.TemporaryDirectory(prefix="slot-test-", dir=Path(__file__).parent) as name:
            repo = Path(name)
            slot = repo / p.SLOT
            slot.parent.mkdir(parents=True)
            slot.write_text('from ibme.hibe.abb10 import ABB10HIBE as CHKPHIBE\nraise RuntimeError("DO_NOT_IMPORT")\n', encoding="utf-8")
            with patch.object(p, "git", side_effect=[p.EXPECTED_HEAD, ""]), patch.object(p, "source_snapshot", return_value={"sha256": "x", "files": {}}):
                result = p.check(repo)
            self.assertEqual(result["first_blocker"], "MOCK_OR_TEACHING_SLOT_DEPENDENCY")
            self.assertFalse(result["ready_for_bounded_smoke"])

    def test_stale_review_never_imports_or_admits(self):
        with tempfile.TemporaryDirectory(prefix="slot-test-", dir=Path(__file__).parent) as name:
            repo = Path(name)
            slot = repo / p.SLOT
            slot.parent.mkdir(parents=True)
            slot.write_text('raise RuntimeError("STALE_REVIEW_MUST_NOT_IMPORT")\n', encoding="utf-8")
            review = {"schema": "CHKP-FUNCTIONAL-SLOT-REVIEW/1", "git_head": p.EXPECTED_HEAD,
                      "source_snapshot_sha256": "old", "backend_class": "CHKPHIBE", "parameter_object": "PARAMS",
                      "component_classes": {name: "Unreviewed" for name in ("public_key", "master", "level1", "level2")},
                      "contract": p.CONTRACT, "review_evidence": "test fixture, not real approval"}
            with patch.object(p, "git", side_effect=[p.EXPECTED_HEAD, ""]), patch.object(p, "source_snapshot", return_value={"sha256": "new", "files": {}}):
                result = p.check(repo, review=review)
            self.assertEqual(result["first_blocker"], "STALE_FUNCTIONAL_REVIEW")
            self.assertFalse(result["ready_for_bounded_smoke"])


if __name__ == "__main__":
    unittest.main(verbosity=2)
