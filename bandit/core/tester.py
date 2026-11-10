#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
import copy
import dataclasses
import logging
import warnings

from bandit.core import constants
from bandit.core import context as b_context
from bandit.core import utils

warnings.formatwarning = utils.warnings_formatter
LOG = logging.getLogger(__name__)


@dataclasses.dataclass
class NosecSkip:
    """Merged suppression decision for a finding.

    The three states mirror the parsed comment states:

    * ``None`` means no nosec comment applies to the line;
    * ``blanket=True`` means a bare nosec suppresses every finding;
    * ``test_ids`` holds the union of valid, explicitly listed ids.

    An all-invalid comment is represented by an empty, non-blanket skip,
    which suppresses nothing; it must never be confused with a blanket
    nosec or with the absence of a comment.
    """

    blanket: bool = False
    test_ids: set = dataclasses.field(default_factory=set)


class BanditTester:
    def __init__(self, testset, debug, nosec_lines, metrics):
        self.results = []
        self.testset = testset
        self.last_result = None
        self.debug = debug
        self.nosec_lines = nosec_lines
        self.metrics = metrics

    def run_tests(self, raw_context, checktype):
        """Runs all tests for a certain type of check, for example

        Runs all tests for a certain type of check, for example 'functions'
        store results in results.

        :param raw_context: Raw context dictionary
        :param checktype: The type of checks to run
        :return: a score based on the number and type of test results with
                extra metrics about nosec comments
        """

        scores = {
            "SEVERITY": [0] * len(constants.RANKING),
            "CONFIDENCE": [0] * len(constants.RANKING),
        }

        tests = self.testset.get_tests(checktype)
        for test in tests:
            name = test.__name__
            # execute test with an instance of the context class
            temp_context = copy.copy(raw_context)
            context = b_context.Context(temp_context)
            try:
                if hasattr(test, "_config"):
                    result = test(context, test._config)
                else:
                    result = test(context)

                if result is not None:
                    nosec_skip = self._get_nosecs_from_contexts(
                        temp_context, test_result=result
                    )

                    if isinstance(temp_context["filename"], bytes):
                        result.fname = temp_context["filename"].decode("utf-8")
                    else:
                        result.fname = temp_context["filename"]
                    result.fdata = temp_context["file_data"]

                    if result.lineno is None:
                        result.lineno = temp_context["lineno"]
                    if result.linerange == []:
                        result.linerange = temp_context["linerange"]
                    if result.col_offset == -1:
                        result.col_offset = temp_context["col_offset"]
                    result.end_col_offset = temp_context.get(
                        "end_col_offset", 0
                    )
                    result.test = name
                    if result.test_id == "":
                        result.test_id = test._test_id

                    # don't skip the test if there was no nosec comment
                    if nosec_skip is not None:
                        # A bare nosec (no test ids) suppresses everything.
                        # A non-blanket skip only suppresses explicitly
                        # listed, valid ids; an all-invalid comment yields
                        # an empty set and therefore suppresses nothing.
                        if nosec_skip.blanket:
                            LOG.debug("skipped, nosec without test number")
                            self.metrics.note_nosec()
                            continue
                        if result.test_id in nosec_skip.test_ids:
                            LOG.debug(
                                f"skipped, nosec for test {result.test_id}"
                            )
                            self.metrics.note_skipped_test()
                            continue

                    self.results.append(result)

                    LOG.debug("Issue identified by %s: %s", name, result)
                    sev = constants.RANKING.index(result.severity)
                    val = constants.RANKING_VALUES[result.severity]
                    scores["SEVERITY"][sev] += val
                    con = constants.RANKING.index(result.confidence)
                    val = constants.RANKING_VALUES[result.confidence]
                    scores["CONFIDENCE"][con] += val
                else:
                    nosec_skip = self._get_nosecs_from_contexts(
                        temp_context
                    )
                    if (
                        nosec_skip is not None
                        and not nosec_skip.blanket
                        and test._test_id in nosec_skip.test_ids
                    ):
                        LOG.warning(
                            f"nosec encountered ({test._test_id}), but no "
                            f"failed test on file "
                            f"{temp_context['filename']}:"
                            f"{temp_context['lineno']}"
                        )

            except Exception as e:
                self.report_error(name, context, e)
                if self.debug:
                    raise
        LOG.debug("Returning scores: %s", scores)
        return scores

    def _get_nosecs_from_contexts(self, context, test_result=None):
        """Build the suppression decision from the relevant nosec comments.

        A nosec on the test result's own line and a nosec anywhere on the
        context's line range (e.g. other lines of a multi-line call) are
        merged. The merge preserves the three-way distinction:

        * no comment on either location -> ``None``;
        * any bare nosec -> a blanket :class:`NosecSkip`;
        * otherwise the union of valid, explicitly listed ids, which may
          be empty when every listed id was invalid.

        :param context: temp context
        :param test_result: optional test result
        :return: a NosecSkip, or None when no nosec comment applies
        """
        base_nosec = (
            self.nosec_lines.get(test_result.lineno)
            if test_result
            else None
        )
        context_nosec = utils.get_nosec(self.nosec_lines, context)

        # if both are none there were no comments; this is explicitly
        # different from a parsed nosec whose ids are all invalid.
        if base_nosec is None and context_nosec is None:
            return None

        blanket = False
        test_ids = set()
        for nosec in (base_nosec, context_nosec):
            if nosec is None:
                continue
            if nosec.blanket:
                blanket = True
            test_ids.update(nosec.test_ids)

        return NosecSkip(blanket=blanket, test_ids=test_ids)

    @staticmethod
    def report_error(test, context, error):
        what = "Bandit internal error running: "
        what += f"{test} "
        what += "on file %s at line %i: " % (
            context._context["filename"],
            context._context["lineno"],
        )
        what += str(error)
        import traceback

        what += traceback.format_exc()
        LOG.error(what)
