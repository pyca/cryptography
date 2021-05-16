import argparse
import subprocess
import sys
from pathlib import Path


def build(workdir):
    python_deps = ["wheel", "setuptools_rust", "click", "requests"]
    debian_deps = ["build-essential", "rustc", "libssl-dev"]
    subprocess.check_call(["apt-get", "update"])
    subprocess.check_call(["apt-get", "install", "--yes", ] + debian_deps)
    subprocess.check_call([sys.executable, "-m", "pip", "install", "--user", ] + python_deps)
    subprocess.check_call(["python3", "setup.py", "bdist_wheel"], cwd=workdir)
    subprocess.check_call(["python3", "setup.py", "bdist_wheel"], cwd=workdir / "vectors")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("workdir", type=Path)
    args = parser.parse_args()
    build(args.workdir)
