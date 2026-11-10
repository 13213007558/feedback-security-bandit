#
# SPDX-License-Identifier: Apache-2.0
import os

import testtools

from bandit.core import config as b_config
from bandit.core import manager as b_manager
from bandit.core import test_set as b_test_set
from bandit.plugins import injection_shell


class ShellTaintFunctionalTests(testtools.TestCase):
    """Functional tests for the optional shell command taint analysis.

    These tests only scan a static example file; no command is ever
    executed and no real environment variable content is read.  The
    reported information is limited to source code positions and
    variable relations.
    """

    def setUp(self):
        super().setUp()
        path = os.path.join(os.getcwd(), "bandit", "plugins")
        b_conf = b_config.BanditConfig()
        cfg = injection_shell.gen_config("shell_injection")
        cfg["source_analysis"] = True
        b_conf.config["shell_injection"] = cfg
        self.b_mgr = b_manager.BanditManager(b_conf, "file")
        self.b_mgr.b_conf._settings["plugins_dir"] = path
        self.b_mgr.b_ts = b_test_set.BanditTestSet(config=b_conf)
        self.b_mgr.discover_files(
            [os.path.join(os.getcwd(), "examples", "shell_taint.py")],
            True,
        )
        self.b_mgr.run_tests()
        self.issues = self.b_mgr.get_issue_list()

    def issue_at(self, lineno, test_id):
        for issue in self.issues:
            if issue.lineno == lineno and issue.test_id == test_id:
                return issue
        self.fail(f"no {test_id} issue at line {lineno}")

    def test_environ_path_is_traceable_line_by_line(self):
        """The report links source, assignments and sink by line."""
        issue = self.issue_at(18, "B602")
        self.assertIn("os.environ (line 16)", issue.text)
        self.assertIn("'target' (line 16)", issue.text)
        self.assertIn("'cmd' (line 17)", issue.text)
        self.assertIn("shell command (line 18)", issue.text)

    def test_argv_path_reported(self):
        issue = self.issue_at(24, "B605")
        self.assertIn("sys.argv (line 22)", issue.text)
        self.assertIn("'script' (line 22)", issue.text)

    def test_input_path_reported(self):
        issue = self.issue_at(30, "B602")
        self.assertIn("input() (line 28)", issue.text)
        self.assertIn("'name' (line 28)", issue.text)

    def test_properly_quoted_word_adds_no_taint_warning(self):
        """shlex.quote of a complete shell word: no new taint alarm."""
        issue = self.issue_at(36, "B602")
        self.assertNotIn("Taint analysis", issue.text)

    def test_quote_nested_in_quotes_is_tainted(self):
        """A quoted value stuffed inside more quotes is not safe."""
        issue = self.issue_at(42, "B602")
        self.assertIn("external input from input() (line 40)", issue.text)

    def test_raw_concat_after_quote_is_tainted(self):
        """Concatenating an unprocessed value after quoting taints."""
        issue = self.issue_at(49, "B602")
        self.assertIn("external input from input() (line 47)", issue.text)

    def test_loop_is_an_explicit_boundary(self):
        """Loops taint through one pass and are marked as boundaries."""
        issue = self.issue_at(56, "B605")
        self.assertIn("sys.argv (line 54)", issue.text)
        self.assertIn("analysis boundary: loop (line 54)", issue.text)

    def test_list_args_with_shell_false_get_no_taint_conclusion(self):
        """Argument lists to shell=False calls are not shell strings."""
        issue = self.issue_at(61, "B603")
        self.assertNotIn("Taint analysis", issue.text)

    def test_unanalyzable_call_is_boundary_not_safe(self):
        issue = self.issue_at(67, "B605")
        self.assertIn(
            "analysis boundary: call to 'build_command' (line 66)",
            issue.text,
        )
        self.assertNotIn("external input", issue.text)

    def test_safe_in_name_is_not_a_sanitizer(self):
        """A function named safe_quote is not accepted as sanitizer."""
        issue = self.issue_at(73, "B605")
        self.assertIn(
            "analysis boundary: call to 'safe_quote' (line 72)",
            issue.text,
        )

    def test_no_real_environment_content_in_output(self):
        """Reports contain positions/variables, never env values."""
        marker = "taint-test-secret-value"
        os.environ["TARGET_HOST"] = marker
        try:
            for issue in self.issues:
                self.assertNotIn(marker, issue.text)
        finally:
            del os.environ["TARGET_HOST"]

    def test_existing_severities_not_downgraded(self):
        """Source analysis must not lower any existing B6xx result."""
        for issue in self.issues:
            if issue.test_id in ("B602", "B605"):
                self.assertEqual("HIGH", issue.severity)
