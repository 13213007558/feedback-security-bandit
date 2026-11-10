#
# SPDX-License-Identifier: Apache-2.0
"""Optional per-file scan result cache.

This module implements a local, opt-in cache that lets Bandit skip
re-running AST plugins for files whose source bytes and scanning
environment have not changed since a previous run.

The cache is stored as plain JSON. JSON is data-only: loading a cache
file can never execute code, unlike pickle-based serialization. Entries
that fail structural validation are treated as corrupted and the
affected files are simply re-scanned.
"""
import hashlib
import inspect
import json
import logging
import os
import sys
import tempfile

import bandit
from bandit.core import constants
from bandit.core import issue as b_issue

LOG = logging.getLogger(__name__)

CACHE_FILE_NAME = "bandit-cache.json"
CACHE_VERSION = 1

_ISSUE_FIELD_TYPES = {
    "severity": str,
    "cwe": int,
    "confidence": str,
    "text": str,
    "test": str,
    "test_id": str,
    "lineno": int,
    "col_offset": int,
    "end_col_offset": int,
    "linerange": list,
}


def _canonicalize(value):
    """Convert config data into a deterministic, JSON-safe structure."""
    if isinstance(value, dict):
        return {
            str(key): _canonicalize(value[key])
            for key in sorted(value, key=str)
        }
    if isinstance(value, (list, tuple)):
        return [_canonicalize(item) for item in value]
    if isinstance(value, (set, frozenset)):
        return sorted((_canonicalize(item) for item in value), key=repr)
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return repr(value)


def _plugin_fingerprint(plugin):
    """Build a stable identity for a single test plugin.

    Returns None when the plugin cannot provide a stable identity (for
    example a dynamically generated callable with no retrievable source).
    Callers must treat that as "cannot cache" and recompute instead.
    """
    try:
        source = inspect.getsource(plugin)
    except (OSError, TypeError):
        return None
    fingerprint = {
        "module": getattr(plugin, "__module__", None),
        "name": getattr(
            plugin, "__qualname__", getattr(plugin, "__name__", None)
        ),
        "test_id": getattr(plugin, "_test_id", None),
        "source_sha256": hashlib.sha256(source.encode("utf-8")).hexdigest(),
    }
    if hasattr(plugin, "_config"):
        fingerprint["config"] = _canonicalize(plugin._config)
    return fingerprint


def compute_run_fingerprint(test_set, ignore_nosec):
    """Fingerprint everything that can change scan results.

    This covers the Bandit version, the Python parse environment, the
    nosec suppression switch, the set of enabled rules, each rule's
    implementation version (source hash) and any rule configuration that
    influences rule behavior. Returns None if any enabled plugin cannot
    provide a stable identity.
    """
    plugins = []
    for extension in getattr(test_set, "plugins", []):
        fingerprint = _plugin_fingerprint(extension.plugin)
        if fingerprint is None:
            LOG.warning(
                "Plugin '%s' does not provide a stable identity; "
                "scan caching is disabled for this run.",
                getattr(extension, "name", extension.plugin),
            )
            return None
        fingerprint["extension"] = getattr(extension, "name", None)
        plugins.append(fingerprint)
    plugins.sort(
        key=lambda item: (
            item.get("test_id") or "",
            item.get("extension") or "",
        )
    )
    material = {
        "bandit_version": bandit.__version__,
        "python_version": list(sys.version_info[:3]),
        "ignore_nosec": bool(ignore_nosec),
        "plugins": plugins,
    }
    blob = json.dumps(material, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(blob.encode("utf-8")).hexdigest()


def issue_to_dict(iss):
    """Serialize an issue to cache-safe data (no path, no file handle)."""
    return {
        "severity": iss.severity,
        "cwe": iss.cwe.id,
        "confidence": iss.confidence,
        "text": iss.text,
        "ident": iss.ident,
        "test": iss.test,
        "test_id": iss.test_id,
        "lineno": iss.lineno,
        "col_offset": iss.col_offset,
        "end_col_offset": iss.end_col_offset,
        "linerange": list(iss.linerange),
    }


def issue_from_dict(data, fname, fdata):
    """Rebuild an issue, binding it to the file scanned in this run."""
    iss = b_issue.Issue(
        severity=data["severity"],
        cwe=data["cwe"],
        confidence=data["confidence"],
        text=data["text"],
        ident=data["ident"],
        lineno=data["lineno"],
        test_id=data["test_id"],
        col_offset=data["col_offset"],
        end_col_offset=data["end_col_offset"],
    )
    iss.test = data["test"]
    iss.linerange = list(data["linerange"])
    iss.fname = fname
    iss.fdata = fdata
    return iss


def _validate_issue(data):
    if not isinstance(data, dict):
        return False
    for field, ftype in _ISSUE_FIELD_TYPES.items():
        if field not in data or not isinstance(data[field], ftype):
            return False
    if data["severity"] not in constants.RANKING:
        return False
    if data["confidence"] not in constants.RANKING:
        return False
    if data["ident"] is not None and not isinstance(data["ident"], str):
        return False
    return all(isinstance(line_no, int) for line_no in data["linerange"])


def _validate_entry(entry):
    """Structural validation so corrupted entries are detected."""
    if not isinstance(entry, dict):
        return False
    if not isinstance(entry.get("source_sha256"), str):
        return False
    issues = entry.get("issues")
    if not isinstance(issues, list):
        return False
    if not all(_validate_issue(item) for item in issues):
        return False
    score = entry.get("score")
    if not isinstance(score, dict):
        return False
    for criteria, _ in constants.CRITERIA:
        values = score.get(criteria)
        if not isinstance(values, list):
            return False
        if len(values) != len(constants.RANKING):
            return False
        if not all(isinstance(value, int) for value in values):
            return False
    file_metrics = entry.get("metrics")
    if not isinstance(file_metrics, dict):
        return False
    return all(
        isinstance(value, (int, float)) for value in file_metrics.values()
    )


class ScanCache:
    """Per-file scan cache backed by a single JSON document."""

    def __init__(self, cache_dir, test_set, ignore_nosec=False):
        self.cache_dir = cache_dir
        self.cache_file = os.path.join(cache_dir, CACHE_FILE_NAME)
        self.fingerprint = compute_run_fingerprint(test_set, ignore_nosec)
        self.enabled = self.fingerprint is not None
        self.entries = {}

    @staticmethod
    def _key(fname):
        # The absolute path is part of the cache identity, so results
        # recorded for one file can never be replayed onto another path.
        return os.path.abspath(fname)

    def load(self):
        """Load cache entries, discarding anything stale or corrupted."""
        if not self.enabled:
            return
        try:
            with open(self.cache_file, encoding="utf-8") as fdata:
                raw = json.load(fdata)
        except FileNotFoundError:
            return
        except (OSError, ValueError):
            LOG.warning(
                "Ignoring corrupted Bandit cache file: %s", self.cache_file
            )
            return
        if not isinstance(raw, dict):
            LOG.warning(
                "Ignoring corrupted Bandit cache file: %s", self.cache_file
            )
            return
        if raw.get("version") != CACHE_VERSION:
            return
        if raw.get("fingerprint") != self.fingerprint:
            # environment, rules or rule configuration changed
            LOG.debug("Cache fingerprint mismatch, rescanning all files")
            return
        files = raw.get("files")
        if not isinstance(files, dict):
            return
        for path, entry in files.items():
            if isinstance(path, str) and _validate_entry(entry):
                self.entries[path] = entry
            else:
                LOG.debug("Dropping corrupted cache entry for %s", path)

    def lookup(self, fname, data):
        """Return the cached entry for fname if it is still valid."""
        if not self.enabled:
            return None
        entry = self.entries.get(self._key(fname))
        if entry is None:
            return None
        digest = hashlib.sha256(data).hexdigest()
        if entry["source_sha256"] != digest:
            return None
        return entry

    def store(self, fname, data, issues, score, file_metrics):
        """Record the complete, unfiltered scan result for one file."""
        if not self.enabled:
            return
        self.entries[self._key(fname)] = {
            "source_sha256": hashlib.sha256(data).hexdigest(),
            "issues": [issue_to_dict(iss) for iss in issues],
            "score": {key: list(val) for key, val in score.items()},
            "metrics": dict(file_metrics),
        }

    def save(self):
        """Persist the cache atomically; failures never break the scan."""
        if not self.enabled:
            return
        try:
            os.makedirs(self.cache_dir, exist_ok=True)
            payload = {
                "version": CACHE_VERSION,
                "fingerprint": self.fingerprint,
                "files": self.entries,
            }
            fd, tmp_name = tempfile.mkstemp(
                dir=self.cache_dir, prefix=".bandit-cache-", suffix=".tmp"
            )
            try:
                with os.fdopen(fd, "w", encoding="utf-8") as fdata:
                    json.dump(payload, fdata, sort_keys=True)
                os.replace(tmp_name, self.cache_file)
            except BaseException:
                try:
                    os.unlink(tmp_name)
                except OSError:
                    pass
                raise
        except OSError as err:
            LOG.warning(
                "Unable to write Bandit cache file %s: %s",
                self.cache_file,
                err,
            )
