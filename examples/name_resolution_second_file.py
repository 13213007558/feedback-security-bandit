"""Second file for cross-file name resolution isolation tests.

This file deliberately has no subprocess import.  A previous file's import
bindings must never leak into the fresh visitor created for this module.
"""

# ``shadow`` is unbound within this file.  With legacy free-name handling this
# still matches the generic shell check, but it must not acquire an imported
# identity from another scanned file.
shadow.run("isolated file", shell=True)
