#
# SPDX-License-Identifier: Apache-2.0
import json
import os
import shutil
import tempfile
import types

import testtools

from bandit.core import cache as b_cache
from bandit.core import config
from bandit.core import constants
from bandit.core import issue
from bandit.core import manager
from bandit.formatters import json as b_json


def _make_eval_plugin(counter, test_id="B999"):
    """A short plugin that counts how often it is invoked."""

    def eval_check(context):
        counter["calls"] += 1
        if context.call_function_name_qual == "eval":
            return issue.Issue(
                severity=constants.MEDIUM,
                cwe=issue.Cwe.OS_COMMAND_INJECTION,
                confidence=constants.HIGH,
                text="Use of eval detected.",
                test_id=test_id,
            )
        return None

    eval_check._test_id = test_id
    eval_check._checks = ["Call"]
    return eval_check


def _make_config_plugin(counter, plugin_config, test_id="B998"):
    """A short plugin whose behavior depends on its configuration."""

    def config_check(context, cfg):
        counter["calls"] += 1
        if context.call_function_name_qual == "eval":
            return issue.Issue(
                severity=constants.MEDIUM,
                cwe=issue.Cwe.OS_COMMAND_INJECTION,
                confidence=constants.HIGH,
                text=cfg["text"],
                test_id=test_id,
            )
        return None

    config_check._test_id = test_id
    config_check._checks = ["Call"]
    config_check._config = plugin_config
    return config_check


class _FakeTestSet:
    """Minimal stand-in for BanditTestSet holding only our plugins."""

    def __init__(self, plugins):
        self.plugins = [
            types.SimpleNamespace(name=plugin.__name__, plugin=plugin)
            for plugin in plugins
        ]
        self.tests = {}
        for plugin in plugins:
            for check in plugin._checks:
                self.tests.setdefault(check, []).append(plugin)

    def get_tests(self, checktype):
        return self.tests.get(checktype, [])


class CacheTests(testtools.TestCase):
    def setUp(self):
        super().setUp()
        self.workdir = tempfile.mkdtemp(prefix="bandit-cache-test-")
        self.addCleanup(shutil.rmtree, self.workdir, ignore_errors=True)
        self.target = os.path.join(self.workdir, "target")
        os.makedirs(self.target)
        self.cache_dir = os.path.join(self.workdir, "cache")

    def _write(self, name, content):
        path = os.path.join(self.target, name)
        with open(path, "w") as fdata:
            fdata.write(content)
        return path

    def _run_scan(self, plugins, cache_dir=None, ignore_nosec=False):
        b_mgr = manager.BanditManager(
            config.BanditConfig(),
            "file",
            ignore_nosec=ignore_nosec,
            cache_dir=cache_dir,
        )
        b_mgr.b_ts = _FakeTestSet(plugins)
        b_mgr.discover_files([self.target], recursive=True)
        b_mgr.run_tests()
        return b_mgr

    def _report_json(
        self, b_mgr, sev_level=constants.LOW, conf_level=constants.LOW
    ):
        fd, path = tempfile.mkstemp(suffix=".json", dir=self.workdir)
        self.addCleanup(os.unlink, path)
        with os.fdopen(fd, "w") as out:
            b_json.report(b_mgr, out, sev_level, conf_level, lines=3)
        with open(path) as fdata:
            data = json.load(fdata)
        data.pop("generated_at", None)
        return data

    def _cache_file(self, cache_dir=None):
        return os.path.join(
            cache_dir or self.cache_dir, b_cache.CACHE_FILE_NAME
        )

    def test_unchanged_files_are_not_rechecked(self):
        self._write("one.py", "eval('1')\n")
        self._write("two.py", "eval('2')\neval('3')\n")

        counter1 = {"calls": 0}
        mgr1 = self._run_scan(
            [_make_eval_plugin(counter1)], cache_dir=self.cache_dir
        )
        self.assertGreater(counter1["calls"], 0)
        self.assertTrue(os.path.exists(self._cache_file()))

        counter2 = {"calls": 0}
        mgr2 = self._run_scan(
            [_make_eval_plugin(counter2)], cache_dir=self.cache_dir
        )
        # cache hit: the plugin never ran, proving no file was re-checked
        self.assertEqual(0, counter2["calls"])

        # results and metrics are identical to a cold scan
        self.assertEqual(
            self._report_json(mgr1), self._report_json(mgr2)
        )

    def test_changed_source_is_rescanned(self):
        self._write("one.py", "eval('1')\n")
        self._write("two.py", "eval('2')\n")

        counter1 = {"calls": 0}
        self._run_scan(
            [_make_eval_plugin(counter1)], cache_dir=self.cache_dir
        )
        self.assertEqual(2, counter1["calls"])

        self._write("two.py", "eval('changed')\n")
        counter2 = {"calls": 0}
        mgr2 = self._run_scan(
            [_make_eval_plugin(counter2)], cache_dir=self.cache_dir
        )
        # only the modified file was re-checked
        self.assertEqual(1, counter2["calls"])

        # results match a completely cold scan of the same tree
        cold_counter = {"calls": 0}
        cold_mgr = self._run_scan(
            [_make_eval_plugin(cold_counter)],
            cache_dir=os.path.join(self.workdir, "cold-cache"),
        )
        self.assertEqual(
            self._report_json(cold_mgr), self._report_json(mgr2)
        )

    def test_rule_config_change_rescans(self):
        self._write("one.py", "eval('1')\n")

        counter1 = {"calls": 0}
        self._run_scan(
            [_make_config_plugin(counter1, {"text": "first"})],
            cache_dir=self.cache_dir,
        )
        self.assertEqual(1, counter1["calls"])

        counter2 = {"calls": 0}
        mgr2 = self._run_scan(
            [_make_config_plugin(counter2, {"text": "second"})],
            cache_dir=self.cache_dir,
        )
        # rule configuration changed: old conclusions were not reused
        self.assertEqual(1, counter2["calls"])

        cold_counter = {"calls": 0}
        cold_mgr = self._run_scan(
            [_make_config_plugin(cold_counter, {"text": "second"})],
            cache_dir=os.path.join(self.workdir, "cold-cache"),
        )
        self.assertEqual(
            self._report_json(cold_mgr), self._report_json(mgr2)
        )

    def test_enabled_rules_change_rescans(self):
        self._write("one.py", "eval('1')\n")

        counter1 = {"calls": 0}
        self._run_scan(
            [_make_eval_plugin(counter1, test_id="B991")],
            cache_dir=self.cache_dir,
        )
        self.assertEqual(1, counter1["calls"])

        counter2a = {"calls": 0}
        counter2b = {"calls": 0}
        mgr2 = self._run_scan(
            [
                _make_eval_plugin(counter2a, test_id="B991"),
                _make_eval_plugin(counter2b, test_id="B992"),
            ],
            cache_dir=self.cache_dir,
        )
        # the enabled rule set changed, so everything was re-checked
        self.assertEqual(1, counter2a["calls"])
        self.assertEqual(1, counter2b["calls"])
        self.assertEqual(2, len(mgr2.get_issue_list()))

    def test_path_change_rescans_and_rebinds_filename(self):
        path = self._write("one.py", "eval('1')\n")

        counter1 = {"calls": 0}
        self._run_scan(
            [_make_eval_plugin(counter1)], cache_dir=self.cache_dir
        )
        self.assertEqual(1, counter1["calls"])

        new_path = os.path.join(self.target, "renamed.py")
        os.rename(path, new_path)

        counter2 = {"calls": 0}
        mgr2 = self._run_scan(
            [_make_eval_plugin(counter2)], cache_dir=self.cache_dir
        )
        # the path is part of the cache identity: file was re-checked
        self.assertEqual(1, counter2["calls"])

        issues = mgr2.get_issue_list()
        self.assertEqual(1, len(issues))
        # the issue is bound to the new path, not the cached old one
        self.assertEqual(new_path, issues[0].fname)
        report = self._report_json(mgr2)
        self.assertEqual(new_path, report["results"][0]["filename"])
        self.assertNotIn("one.py", json.dumps(report))

    def test_ignore_nosec_change_rescans(self):
        self._write("one.py", "eval('1')  # nosec\n")

        counter1 = {"calls": 0}
        mgr1 = self._run_scan(
            [_make_eval_plugin(counter1)], cache_dir=self.cache_dir
        )
        self.assertEqual(0, len(mgr1.get_issue_list()))
        self.assertEqual(1, mgr1.metrics.data["_totals"]["nosec"])

        counter2 = {"calls": 0}
        mgr2 = self._run_scan(
            [_make_eval_plugin(counter2)],
            cache_dir=self.cache_dir,
            ignore_nosec=True,
        )
        # ignore_nosec changed: the suppressed result was not reused
        self.assertEqual(1, counter2["calls"])
        self.assertEqual(1, len(mgr2.get_issue_list()))
        self.assertEqual(0, mgr2.metrics.data["_totals"]["nosec"])

        cold_counter = {"calls": 0}
        cold_mgr = self._run_scan(
            [_make_eval_plugin(cold_counter)],
            cache_dir=os.path.join(self.workdir, "cold-cache"),
            ignore_nosec=True,
        )
        self.assertEqual(
            self._report_json(cold_mgr), self._report_json(mgr2)
        )

    def test_corrupted_cache_file_is_rescanned(self):
        self._write("one.py", "eval('1')\n")

        counter1 = {"calls": 0}
        mgr1 = self._run_scan(
            [_make_eval_plugin(counter1)], cache_dir=self.cache_dir
        )

        with open(self._cache_file(), "w") as fdata:
            fdata.write("this is not json {{{")

        counter2 = {"calls": 0}
        mgr2 = self._run_scan(
            [_make_eval_plugin(counter2)], cache_dir=self.cache_dir
        )
        self.assertEqual(counter1["calls"], counter2["calls"])
        self.assertEqual(
            self._report_json(mgr1), self._report_json(mgr2)
        )

    def test_corrupted_cache_entry_is_rescanned(self):
        self._write("one.py", "eval('1')\n")
        self._write("two.py", "eval('2')\n")

        counter1 = {"calls": 0}
        mgr1 = self._run_scan(
            [_make_eval_plugin(counter1)], cache_dir=self.cache_dir
        )

        with open(self._cache_file()) as fdata:
            payload = json.load(fdata)
        victim = os.path.abspath(os.path.join(self.target, "one.py"))
        payload["files"][victim] = {"issues": "garbage"}
        with open(self._cache_file(), "w") as fdata:
            json.dump(payload, fdata)

        counter2 = {"calls": 0}
        mgr2 = self._run_scan(
            [_make_eval_plugin(counter2)], cache_dir=self.cache_dir
        )
        # only the file with the corrupted entry was re-checked
        self.assertEqual(1, counter2["calls"])
        self.assertEqual(
            self._report_json(mgr1), self._report_json(mgr2)
        )

    def test_failed_scan_is_not_cached(self):
        self._write("good.py", "eval('1')\n")
        bad_path = self._write("bad.py", "def broken(:\n")

        counter1 = {"calls": 0}
        mgr1 = self._run_scan(
            [_make_eval_plugin(counter1)], cache_dir=self.cache_dir
        )
        self.assertEqual(1, len(mgr1.skipped))

        with open(self._cache_file()) as fdata:
            payload = json.load(fdata)
        cached_paths = payload["files"].keys()
        self.assertIn(
            os.path.abspath(os.path.join(self.target, "good.py")),
            cached_paths,
        )
        # a file that failed to scan is never marked complete
        self.assertNotIn(os.path.abspath(bad_path), cached_paths)

        self._write("bad.py", "eval('2')\n")
        counter2 = {"calls": 0}
        mgr2 = self._run_scan(
            [_make_eval_plugin(counter2)], cache_dir=self.cache_dir
        )
        self.assertEqual(0, len(mgr2.skipped))
        # only the previously failed file was scanned now
        self.assertEqual(1, counter2["calls"])
        self.assertEqual(2, len(mgr2.get_issue_list()))

    def test_severity_filter_applies_to_current_request(self):
        self._write("one.py", "eval('1')\n")

        counter1 = {"calls": 0}
        mgr1 = self._run_scan(
            [_make_eval_plugin(counter1)], cache_dir=self.cache_dir
        )

        counter2 = {"calls": 0}
        mgr2 = self._run_scan(
            [_make_eval_plugin(counter2)], cache_dir=self.cache_dir
        )
        self.assertEqual(0, counter2["calls"])

        # filtering runs against the current request, cached data holds
        # the complete unfiltered result set
        for mgr in (mgr1, mgr2):
            low = self._report_json(mgr, sev_level=constants.LOW)
            high = self._report_json(mgr, sev_level=constants.HIGH)
            self.assertEqual(1, len(low["results"]))
            self.assertEqual(0, len(high["results"]))

    def test_baseline_filter_applies_to_current_request(self):
        self._write("one.py", "eval('1')\n")

        counter1 = {"calls": 0}
        mgr1 = self._run_scan(
            [_make_eval_plugin(counter1)], cache_dir=self.cache_dir
        )
        baseline_data = json.dumps(
            {"results": [i.as_dict() for i in mgr1.get_issue_list()]}
        )

        counter2 = {"calls": 0}
        mgr2 = self._run_scan(
            [_make_eval_plugin(counter2)], cache_dir=self.cache_dir
        )
        self.assertEqual(0, counter2["calls"])
        mgr2.populate_baseline(baseline_data)
        self.assertEqual(0, mgr2.results_count())

    def test_plugin_without_stable_identity_disables_cache(self):
        self._write("one.py", "eval('1')\n")

        def make_dynamic_plugin(counter):
            # a function defined via exec has no retrievable source,
            # so it cannot provide a stable identity for the cache
            namespace = {"counter": counter}
            exec(
                "def dynamic_plugin(context):\n"
                "    counter['calls'] += 1\n"
                "    return None\n",
                namespace,
            )
            plugin = namespace["dynamic_plugin"]
            plugin._test_id = "B990"
            plugin._checks = ["Call"]
            return plugin

        counter1 = {"calls": 0}
        self._run_scan(
            [make_dynamic_plugin(counter1)], cache_dir=self.cache_dir
        )
        self.assertGreater(counter1["calls"], 0)
        # nothing was cached because no stable identity exists
        self.assertFalse(os.path.exists(self._cache_file()))

        counter2 = {"calls": 0}
        self._run_scan(
            [make_dynamic_plugin(counter2)], cache_dir=self.cache_dir
        )
        # the file was re-checked rather than reusing a cached result
        self.assertGreater(counter2["calls"], 0)

    def test_cache_disabled_without_cache_dir(self):
        self._write("one.py", "eval('1')\n")

        counter1 = {"calls": 0}
        mgr1 = self._run_scan([_make_eval_plugin(counter1)])
        counter2 = {"calls": 0}
        mgr2 = self._run_scan([_make_eval_plugin(counter2)])
        self.assertEqual(counter1["calls"], counter2["calls"])
        self.assertEqual(
            self._report_json(mgr1), self._report_json(mgr2)
        )
