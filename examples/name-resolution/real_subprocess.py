import subprocess

# The unshadowed import is still recognized as a real subprocess call.
subprocess.Popen(["ls"], shell=True)
