"""Exercise lexical name resolution across Python scopes.

The B602 checks below must fire only when the call's root name is really an
imported ``subprocess`` binding.  Local objects that merely share a name are
reported by the generic B604 check instead.
"""

import subprocess
import subprocess as sp


def parameter_shadow(subprocess):
    # ``subprocess`` is a parameter here, not the imported module.
    subprocess.run("parameter", shell=True)


def closure():
    def inner():
        # The enclosing module import is a real closure binding.
        subprocess.run("closure", shell=True)

    inner()


class ClassScope:
    import subprocess as class_import

    def method(self):
        # A class body is not a closure for its methods, so class_import is
        # an unbound free name inside this function.
        class_import.run("class method", shell=True)


lambda_shadow = lambda subprocess: subprocess.run("lambda", shell=True)
lambda_closure = lambda: subprocess.run("lambda closure", shell=True)

# The comprehension has its own scope; the outer iterable and element
# expression still see the module-level import.
values = [
    subprocess.run(item, shell=True) for item in subprocess.arguments
]


def matching_branches(flag):
    if flag:
        chosen = sp
    else:
        chosen = sp
    # Both branches bind the same imported object.
    chosen.run("matching branches", shell=True)


def conflicting_branches(flag):
    if flag:
        chosen = sp
    else:
        chosen = object()
    # Conflicting bindings make the origin unresolvable.
    chosen.run("conflicting branches", shell=True)


subprocess = object()
# Sequential rebinding replaces the earlier import for the rest of the module.
subprocess.run("rebound module name", shell=True)

# A bare imported call is still recognized through the from-import alias.
from subprocess import Popen as popen

popen("from import alias", shell=True)
