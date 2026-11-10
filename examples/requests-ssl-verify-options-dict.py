import httpx
import requests

URL = "https://gmail.com"


def literal_dict_expansion():
    options = {"verify": False, "timeout": 30}
    requests.get(URL, timeout=30, **options)  # ERROR: verify=False via **options


def false_then_true():
    options = {"verify": False}
    options["verify"] = True
    requests.get(URL, timeout=30, **options)  # OK: overwritten before the request


def branch_merge(cond):
    if cond:
        options = {"verify": False}
    else:
        options = {"verify": True}
    requests.get(URL, timeout=30, **options)  # ERROR: False on one path (MEDIUM confidence)


def shallow_copy_independent():
    base = {"verify": True}
    options = dict(base)
    options["verify"] = False
    requests.get(URL, timeout=30, **options)  # ERROR: the copy disables verification
    requests.get(URL, timeout=30, **base)  # OK: the original dict is untouched


def copy_method():
    base = {"verify": True}
    options = base.copy()
    options["verify"] = False
    requests.post(URL, timeout=30, **options)  # ERROR


def alias_assignment():
    options = {"verify": True}
    alias = options
    alias["verify"] = False
    requests.get(URL, timeout=30, **options)  # ERROR: mutated through the alias


def update_with_literal():
    options = {"timeout": 30}
    options.update({"verify": False})
    requests.get(URL, timeout=30, **options)  # ERROR


def update_with_unknown():
    options = {"verify": True}
    options.update(load_settings())
    requests.get(URL, timeout=30, **options)  # OK: unknown update, cannot confirm


def unknown_call_may_mutate():
    options = {"verify": False}
    configure(options)
    requests.get(URL, timeout=30, **options)  # OK: unknown call may have changed it


def inline_expansion():
    requests.get(URL, timeout=30, **{"verify": False})  # ERROR


def expansion_order():
    options = {"verify": False}
    requests.get(URL, timeout=30, **options, verify=True)  # OK: later keyword wins
    requests.get(URL, timeout=30, verify=True, **options)  # ERROR: later ** wins


def unrelated_content():
    options = {"verify": "False", "mode": "verify"}
    requests.get(URL, timeout=30, **options)  # OK: string "False" is not False


def loop_bounded(retries):
    options = {"timeout": 30}
    for attempt in range(retries):
        options["verify"] = False
    requests.get(URL, timeout=30, **options)  # ERROR


def httpx_options():
    options = {"verify": False}
    httpx.get(URL, **options)  # ERROR
    client_options = {"verify": False}
    httpx.Client(**client_options)  # ERROR
    safe_options = {"verify": True}
    httpx.get(URL, **safe_options)  # OK
