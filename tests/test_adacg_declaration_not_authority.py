"""A valid agent declaration is not current authority to execute an action.

The W3C Agent Declaration and Assurance Community Group is chartered to specify
Agent Declaration (how an agent presents its capabilities and guardrails), Agent
Assurance (how external systems verify those claims at runtime), an Open KYA
Manifest, and graduated Core / Deploy / Transact conformance profiles.

Declaration and assurance are both in that scope. Authorization is not. The
tempting jump is that once a declaration is signed and verified, a downstream
system may read it as "this agent may do X". This module denies that jump in
executable form, against the real adapter rather than against a description of
it.

The vectors live in `conformance/adacg-declaration-not-authority-v1.json` so an
implementation in any language can reproduce the same outcomes. The declaration
in that file is carried deliberately: it is a complete, valid, Transact-profile,
TEE-bound manifest, and it has no effect on any outcome here.
"""

from __future__ import annotations

import copy
import inspect
import json
import sys
import unittest
from pathlib import Path

from border.mandate_adapter import MandateAdapterError, MandateAuthorityAdapter

# `unittest discover -s tests` puts this directory on sys.path, so the sibling
# module imports bare. Doing it explicitly means the file also runs under
# `python -m unittest tests.test_adacg_declaration_not_authority`, and a
# regression test that only runs one of the two ways is half a regression test.
sys.path.insert(0, str(Path(__file__).parent))

from test_mandate_adapter import (  # noqa: E402
    context,
    executor_authority,
    executor_credential,
    mandate,
    request_authority,
)

ROOT = Path(__file__).parents[1]
VECTORS = ROOT / "conformance" / "adacg-declaration-not-authority-v1.json"


class DeclarationIsNotAuthorityTests(unittest.TestCase):

    def setUp(self):
        self.corpus = json.loads(VECTORS.read_text())

    def _run_case(self, case):
        """Build the baseline artifacts, apply the case mutation, run the adapter."""
        action = copy.deepcopy(self.corpus["baseline"]["action"])
        declaration = copy.deepcopy(self.corpus["declaration"])
        overrides = {}

        mutation = case["mutation"]
        if mutation == "executor_authorizes=false":
            overrides["executor_authorizes"] = lambda _record, _action: False
        elif mutation == "request_authorizes=false":
            overrides["request_authorizes"] = lambda _record, _action: False
        elif mutation == "action.target=notion:page:999":
            action["target"] = "notion:page:999"
        elif mutation == "declaration=null":
            declaration = None
        elif mutation == "relationship=DELEGATE":
            pass  # applied to the mandate below
        elif mutation is not None:
            self.fail(f"unhandled mutation: {mutation!r}")

        request = request_authority()
        executor = executor_authority()
        credential = executor_credential(executor)
        instrument = mandate(request)
        if mutation == "relationship=DELEGATE":
            instrument["relationship"] = "DELEGATE"

        # The declaration is prepared, valid, and then simply has nowhere to go:
        # `normalize` takes no declaration argument. That is the finding, not an
        # oversight in this test.
        self.assertIn(declaration, (None, self.corpus["declaration"]))

        adapter = MandateAuthorityAdapter(context(**overrides))
        return adapter.normalize(instrument, request, executor, credential, action)

    def test_vectors(self):
        for case in self.corpus["cases"]:
            with self.subTest(case=case["id"]):
                if case["expected"] == "admit":
                    receipt = self._run_case(case)
                    self.assertEqual("MANDATE", receipt["relationship"])
                elif case["expected"] == "fail_closed":
                    # The reason is pinned, not just the refusal. A case that
                    # began failing for an unrelated cause would still satisfy a
                    # bare assertRaises while no longer demonstrating anything.
                    with self.assertRaisesRegex(MandateAdapterError, case["reason"]):
                        self._run_case(case)
                else:
                    self.fail(f"unknown expectation: {case['expected']!r}")

    def test_the_corpus_carries_a_positive_control(self):
        """Every case failing closed is also what a broken harness looks like."""
        admits = [c for c in self.corpus["cases"] if c["expected"] == "admit"]
        self.assertTrue(admits, "a negative corpus with no admitting case proves nothing")

    def test_the_authority_decision_takes_no_declaration(self):
        """The structural half, and the stronger one.

        A declaration cannot fail to grant authority here for a policy reason
        that some later revision might soften. It cannot grant authority because
        it is not an input: there is no parameter to pass it to.
        """
        parameters = list(inspect.signature(MandateAuthorityAdapter.normalize).parameters)
        self.assertEqual(
            ["self", "mandate", "request_authority", "executor_authority",
             "executor_credential", "action"],
            parameters,
        )
        for name in parameters:
            self.assertNotIn("declar", name.lower())
            self.assertNotIn("manifest", name.lower())
            self.assertNotIn("kya", name.lower())

    def test_removing_the_declaration_changes_nothing(self):
        """Declaration and authority are not two degrees of the same thing."""
        with_declaration = self._run_case(
            {"id": "with", "mutation": None, "expected": "admit"})
        without_declaration = self._run_case(
            {"id": "without", "mutation": "declaration=null", "expected": "admit"})
        self.assertEqual(with_declaration, without_declaration)

    def test_the_declared_capability_matches_the_denied_action(self):
        """Guard against the corpus quietly ceasing to demonstrate its point.

        NEG-001 is only interesting because the declaration names the very
        capability being refused. If the two drifted apart, the case would be
        refusing an action nobody claimed, which is a different and much weaker
        statement.
        """
        self.assertIn(
            self.corpus["baseline"]["action"]["type"],
            self.corpus["declaration"]["declared_capabilities"],
        )
        self.assertEqual("Transact", self.corpus["declaration"]["conformance_profile"])
        neg_001 = next(
            c for c in self.corpus["cases"]
            if c["id"] == "declaration_valid_but_executor_lacks_current_authority")
        self.assertEqual("fail_closed", neg_001["expected"])


if __name__ == "__main__":
    unittest.main()
