import os
import shlex
import subprocess
import sys


def build_command(base):
    return "run " + base


def safe_quote(value):
    return value


def environ_to_shell():
    target = os.environ["TARGET_HOST"]
    cmd = "ping -c1 " + target
    subprocess.call(cmd, shell=True)


def argv_to_shell():
    script = sys.argv[1]
    cmd = "sh %s" % script
    os.system(cmd)


def input_to_shell():
    name = input("name: ")
    cmd = "echo {}".format(name)
    subprocess.Popen(cmd, shell=True)


def quoted_full_word():
    name = input("name: ")
    cmd = "echo " + shlex.quote(name)
    subprocess.call(cmd, shell=True)


def quoted_inside_quotes():
    name = input("name: ")
    cmd = "echo '" + shlex.quote(name) + "'"
    subprocess.call(cmd, shell=True)


def quoted_then_concat_raw():
    name = input("name: ")
    other = input("other: ")
    cmd = "echo " + shlex.quote(name) + other
    subprocess.call(cmd, shell=True)


def loop_boundary():
    cmd = "echo"
    for word in sys.argv[1:]:
        cmd += " " + word
    os.system(cmd)


def list_args_no_shell():
    target = os.environ["TARGET_HOST"]
    subprocess.call(["ping", "-c1", target])


def unknown_call_boundary():
    base = os.environ["BASE"]
    cmd = build_command(base)
    os.system(cmd)


def safe_name_is_not_a_sanitizer():
    name = input("name: ")
    cmd = "echo " + safe_quote(name)
    os.system(cmd)
