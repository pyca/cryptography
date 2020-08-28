"""A test runner for pywin32"""
from __future__ import print_function
import sys
import os
import site
import subprocess

# locate the dirs based on where this script is - it may be either in the
# source tree, or in an installed Python 'Scripts' tree.
this_dir = os.path.dirname(__file__)
site_packages = [site.getusersitepackages(), ] + site.getsitepackages()

# Run a test using subprocess and wait for the result.
# If we get an returncode != 0, we know that there was an error.
def run_test(script, cmdline_rest=""):
    dirname, scriptname = os.path.split(script)
    # some tests prefer to be run from their directory.
    cmd = [sys.executable, "-u", scriptname] + cmdline_rest.split()
    print(script)
    popen = subprocess.Popen(cmd, shell=True, cwd=dirname,
                             stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    data = popen.communicate()[0]
    if sys.version_info > (3,):
        sys.stdout.write(data.decode('latin-1'))
    else:
        sys.stdout.write(data)
    sys.stdout.flush()
    if popen.returncode:
        print("****** %s failed: %s" % (script, popen.returncode))
        sys.exit(popen.returncode)


def find_and_run(possible_locations, script, cmdline_rest=""):
    for maybe in possible_locations:
        if os.path.isfile(os.path.join(maybe, script)):
            run_test(os.path.abspath(os.path.join(maybe, script)), cmdline_rest)
            break
    else:
        raise RuntimeError("Failed to locate the test script '%s' in one of %s"
                           % (script, possible_locations))

if __name__ == '__main__':
    import argparse

    code_directories = [this_dir] + site_packages

    parser = argparse.ArgumentParser(description="A script to trigger tests in all subprojects of PyWin32.")
    parser.add_argument("-no-user-interaction",
                        default=False,
                        action='store_true',
                        help="Run all tests without user interaction")

    args = parser.parse_args()

    # win32
    maybes = [os.path.join(directory, "win32", "test") for directory in code_directories]
    command = ('testall.py', )
    if args.no_user_interaction:
        command += ("-no-user-interaction", )
    find_and_run(maybes, *command)

    # win32com
    maybes = [os.path.join(directory, "win32com", "test") for directory in [os.path.join(this_dir, "com"), ] + site_packages]
    find_and_run(maybes, 'testall.py', "2")

    # adodbapi
    maybes = [os.path.join(directory, "adodbapi", "test") for directory in code_directories]
    find_and_run(maybes, 'adodbapitest.py')
    # This script has a hard-coded sql server name in it, (and markh typically
    # doesn't have a different server to test on) but there is now supposed to be a server out there on the Internet
    # just to run these tests, so try it...
    find_and_run(maybes, 'test_adodbapi_dbapi20.py')

    if sys.version_info > (3,):
        print("** The tests have some issues on py3k - not all failures are a problem...")
