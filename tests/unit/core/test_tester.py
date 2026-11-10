#
# Copyright 2026 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import testtools

from bandit.core import manager
from bandit.core import tester as b_tester


class NosecMergeTests(testtools.TestCase):
    def _tester(self, nosec_lines):
        return b_tester.BanditTester(
            testset=None,
            debug=False,
            nosec_lines=nosec_lines,
            metrics=None,
        )

    def test_no_comment_returns_none(self):
        bt = self._tester({})
        self.assertIsNone(
            bt._get_nosecs_from_contexts({"linerange": [1]})
        )

    def test_bare_nosec_is_blanket(self):
        nosec_lines = {2: manager.NosecComment(2, blanket=True)}
        bt = self._tester(nosec_lines)
        skip = bt._get_nosecs_from_contexts({"linerange": [1, 2]})
        self.assertIsNotNone(skip)
        self.assertTrue(skip.blanket)
        self.assertEqual(set(), skip.test_ids)

    def test_all_invalid_comment_suppresses_nothing(self):
        nosec_lines = {
            3: manager.NosecComment(
                3, blanket=False, test_ids=set(), invalid_tokens=["B999999"]
            )
        }
        bt = self._tester(nosec_lines)
        skip = bt._get_nosecs_from_contexts({"linerange": [3]})
        self.assertIsNotNone(skip)
        self.assertFalse(skip.blanket)
        self.assertEqual(set(), skip.test_ids)

    def test_partial_valid_merges_only_valid_ids(self):
        nosec_lines = {
            4: manager.NosecComment(
                4,
                blanket=False,
                test_ids={"B602"},
                invalid_tokens=["B999999"],
            )
        }
        bt = self._tester(nosec_lines)

        class Result:
            lineno = 4

        skip = bt._get_nosecs_from_contexts(
            {"linerange": [4]}, test_result=Result()
        )
        self.assertFalse(skip.blanket)
        self.assertEqual({"B602"}, skip.test_ids)

    def test_merge_result_line_and_multiline_context(self):
        # A rule-specific nosec on the result line and a bare nosec on a
        # later line of the multi-line call merge: the result is blanket
        # but still carries the explicit id.
        nosec_lines = {
            5: manager.NosecComment(
                5, blanket=False, test_ids={"B602"}
            ),
            6: manager.NosecComment(6, blanket=True),
        }
        bt = self._tester(nosec_lines)

        class Result:
            lineno = 5

        skip = bt._get_nosecs_from_contexts(
            {"linerange": [6, 7]}, test_result=Result()
        )
        self.assertTrue(skip.blanket)
        self.assertEqual({"B602"}, skip.test_ids)

    def test_merge_two_invalid_comments_stays_non_blanket(self):
        nosec_lines = {
            5: manager.NosecComment(
                5, blanket=False, invalid_tokens=["B999999"]
            ),
            6: manager.NosecComment(
                6, blanket=False, invalid_tokens=["B888888"]
            ),
        }
        bt = self._tester(nosec_lines)

        class Result:
            lineno = 5

        skip = bt._get_nosecs_from_contexts(
            {"linerange": [5, 6]}, test_result=Result()
        )
        self.assertIsNotNone(skip)
        self.assertFalse(skip.blanket)
        self.assertEqual(set(), skip.test_ids)
