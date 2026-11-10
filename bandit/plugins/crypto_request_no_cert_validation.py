#
# Copyright 2014 Hewlett-Packard Development Company, L.P.
#
# SPDX-License-Identifier: Apache-2.0
r"""
=============================================
B501: Test for missing certificate validation
=============================================

Encryption in general is typically critical to the security of many
applications.  Using TLS can greatly increase security by guaranteeing the
identity of the party you are communicating with.  This is accomplished by one
or both parties presenting trusted certificates during the connection
initialization phase of TLS.

When HTTPS request methods are used, certificates are validated automatically
which is the desired behavior.  If certificate validation is explicitly turned
off Bandit will return a HIGH severity error.

This test also follows request option dictionaries built up inside the
same function (dict literals, item assignment, copies, ``update()`` and
``**`` expansion) to detect ``verify=False`` passed indirectly, e.g. via
``requests.get(url, **options)``.  Findings through such indirect paths
report the line where ``verify`` was set to ``False`` as well as the
request itself, and use MEDIUM confidence when the value is only
``False`` on some code paths.


:Example:

.. code-block:: none

    >> Issue: [request_with_no_cert_validation] Call to requests with
    verify=False disabling SSL certificate checks, security issue.
       Severity: High   Confidence: High
       CWE: CWE-295 (https://cwe.mitre.org/data/definitions/295.html)
       Location: examples/requests-ssl-verify-disabled.py:4
    3   requests.get('https://gmail.com', verify=True)
    4   requests.get('https://gmail.com', verify=False)
    5   requests.post('https://gmail.com', verify=True)

.. seealso::

 - https://security.openstack.org/guidelines/dg_move-data-securely.html
 - https://security.openstack.org/guidelines/dg_validate-certificates.html
 - https://cwe.mitre.org/data/definitions/295.html

.. versionadded:: 0.9.0

.. versionchanged:: 1.7.3
    CWE information added

.. versionchanged:: 1.7.5
    Added check for httpx module

.. versionchanged:: 1.9.0
    Added tracking of verify=False passed through ``**options`` dicts

"""
import bandit
from bandit.core import dict_key_tracker
from bandit.core import issue
from bandit.core import test_properties as test
from bandit.core import utils

_HTTP_VERBS = {"get", "options", "head", "post", "put", "patch", "delete"}
_HTTPX_ATTRS = {"request", "stream", "Client", "AsyncClient"} | _HTTP_VERBS


def _match_qualname(qualname, name):
    """Check a qualified call name against the requests/httpx verbs."""
    return (
        qualname == "requests"
        and name in _HTTP_VERBS
        or qualname == "httpx"
        and name in _HTTPX_ATTRS
    )


def _is_request_call(import_aliases):
    """Build a sink predicate matching the calls this plugin checks."""

    def matches(node):
        qualname = utils.get_call_name(node, import_aliases)
        if not qualname:
            return False
        parts = qualname.split(".")
        return _match_qualname(parts[0], parts[-1])

    return matches


@test.checks("Call")
@test.test_id("B501")
def request_with_no_cert_validation(context):
    qualname = context.call_function_name_qual.split(".")[0]

    if not _match_qualname(qualname, context.call_function_name):
        return

    if context.check_call_arg_value("verify", "False"):
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.IMPROPER_CERT_VALIDATION,
            text=f"Call to {qualname} with verify=False disabling SSL "
            "certificate checks, security issue.",
            lineno=context.get_lineno_for_call_arg("verify"),
        )

    # no explicit verify=False keyword: check whether a request options
    # dict expanded via **options sets verify=False instead
    call_node = context.node
    if not any(keyword.arg is None for keyword in call_node.keywords):
        return

    tracked = dict_key_tracker.resolve_key_at_call(
        call_node,
        "verify",
        context.import_aliases,
        _is_request_call(context.import_aliases),
    )
    if tracked is None:
        return

    if tracked.level == dict_key_tracker.FALSE:
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.HIGH,
            cwe=issue.Cwe.IMPROPER_CERT_VALIDATION,
            text=f"Call to {qualname} with verify=False (set in request "
            f"options at line {tracked.source}) disabling SSL "
            "certificate checks, security issue.",
        )
    if tracked.level == dict_key_tracker.MAYBE_FALSE:
        return bandit.Issue(
            severity=bandit.HIGH,
            confidence=bandit.MEDIUM,
            cwe=issue.Cwe.IMPROPER_CERT_VALIDATION,
            text=f"Call to {qualname} may disable SSL certificate "
            "checks: verify=False is set in request options at line "
            f"{tracked.source} on some code paths, security issue.",
        )
