import subprocess

# Explicit list (colon) with an unknown id: nothing may be suppressed.
# Previously the empty resolved set was read as a blanket nosec and hid
# both findings on this line.
subprocess.Popen('/bin/ls *', shell=True)  # nosec: B999999

# Mixed valid and unknown ids: the valid id still suppresses its rule,
# the unknown id is reported and the other rule stays visible.
subprocess.Popen('/bin/ls *', shell=True)  # nosec: B607, B999999

# Full test names resolve to their short ids and suppress the same rule.
subprocess.Popen(
    '/bin/ls *', shell=True
)  # nosec: subprocess_popen_with_shell_equals_true

# Duplicate ids collapse to a single suppression entry.
subprocess.Popen('/bin/ls *', shell=True)  # nosec: B602, B602

# A bare nosec still suppresses every finding on the line.
subprocess.Popen('/bin/ls *', shell=True)  # nosec

# Multi-line call: the comment is attached to the kwarg line and the
# unknown id must not suppress the finding spanning the whole call.
subprocess.Popen('/bin/ls *',
                 shell=True)  # nosec: B999999

# A '# nosec' inside a string is not a comment and suppresses nothing.
subprocess.Popen('# nosec', shell=True)
