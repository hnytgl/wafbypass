import os
import getpass
import subprocess
from setuptools import setup, find_packages

from lib.settings import VERSION
from lib.formatter import fatal, error
from lib.firewall_found import request_issue_creation


try:
    raw_input
except:
    raw_input = input


needs_username_fix = os.getuid() == 0

try:
    if needs_username_fix:
        username = raw_input("what is your username (needed for directory fixes): ")
    else:
        username = getpass.getuser()
    subprocess.call(["bash", "install_helper.sh"])
    setup(
        name='wafbypass',
        version=VERSION,
        packages=find_packages(),
        url='https://github.com/hnytgl/wafbypass',
        license='GPLv3',
        author='hnytgl',
        author_email='',
        description='Advanced WAF detection and bypass tool - 高级WAF防火墙检测与绕过工具',
        scripts=["wafbypass"],
        install_requires=open("requirements.txt").read().split("\n")
    )
    if needs_username_fix:
        if "root" == username:
            # fixes weird docker issues
            path = "/root/.wafbypass"
        else:
            path = "/home/{}/.wafbypass".format(os.path.expanduser(username))
        subprocess.call(["chown", "-R", "{u}:{u}".format(u=username), path])
except Exception as e:
    import sys, traceback

    sep = "-" * 30
    fatal(
        "WAFBypass has caught an unhandled exception with the error message: '{}'.".format(str(e))
    )
    exception_data = "Traceback (most recent call):\n{}{}".format(
        "".join(traceback.format_tb(sys.exc_info()[2])), str(e)
    )
    error(
        "\n{}\n{}\n{}".format(
            sep, exception_data, sep
        )
    )
    request_issue_creation(exception_data)
