import subprocess


class Service:
    def handle(self, subprocess):
        # The parameter shadows the module-level import inside this method.
        # This is an ordinary object's method, not subprocess.Popen.
        subprocess.Popen(["ls"], shell=True)


# An unshadowed import at module scope is still a real subprocess call.
subprocess.Popen(["ls"], shell=True)
