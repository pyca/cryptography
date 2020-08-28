import subprocess
import unyt
import os
import sys
import tempfile


def test_flake8():
    unyt_dir = os.path.dirname(os.path.abspath(unyt.__file__))
    output_file = os.path.join(tempfile.mkdtemp(), "flake8.out")
    if os.path.exists(output_file):
        os.remove(output_file)
    output_string = "--output-file=%s" % output_file
    config_string = "--config=%s" % os.path.join(os.path.dirname(unyt_dir), "setup.cfg")
    subprocess.call(
        [sys.executable, "-m", "flake8", output_string, config_string, unyt_dir]
    )

    if os.path.exists(output_file):
        with open(output_file) as f:
            flake8_output = f.readlines()
        if flake8_output != []:
            raise AssertionError(
                "flake8 found style errors:\n\n%s" % "\n".join(flake8_output)
            )


def test_black():
    unyt_dir = os.path.dirname(os.path.abspath(unyt.__file__))
    p = subprocess.Popen(
        [sys.executable, "-m", "black", "--check", "--diff", unyt_dir],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    output = p.communicate()
    if p.returncode and b"No module named black" not in output[1]:
        raise AssertionError(
            "Black would make code changes, please run black and commit those changes. "
            "Output from black was:\n%s\n%s" % (output[0].decode(), output[1].decode())
        )
